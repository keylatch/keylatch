package brokerd

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func pemOf(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

type fakeLink struct {
	sign func(Challenge) ([]byte, error)
	got  []Challenge
}

func (f *fakeLink) Sign(_ context.Context, _ uint32, c Challenge) ([]byte, error) {
	f.got = append(f.got, c)
	return f.sign(c)
}

type staticKeys map[uint32]crypto.PublicKey

func (s staticKeys) PresenceKey(uid uint32) (crypto.PublicKey, error) {
	if k, ok := s[uid]; ok {
		return k, nil
	}
	return nil, ErrNoPresenceKey
}

func ecSigner(t *testing.T) (*ecdsa.PrivateKey, func(Challenge) ([]byte, error)) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, func(c Challenge) ([]byte, error) {
		sum := sha256.Sum256(c.Message())
		return ecdsa.SignASN1(rand.Reader, k, sum[:])
	}
}

func rsaSigner(t *testing.T) (*rsa.PrivateKey, func(Challenge) ([]byte, error)) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, func(c Challenge) ([]byte, error) {
		sum := sha256.Sum256(c.Message())
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	}
}

func verifyAs(platform string, keys KeyStore, link HelperLink) error {
	p := &SignedPresence{Platform: platform, Keys: keys, Link: link}
	return p.Verify(context.Background(), Subject{UID: 501, PID: 7, Start: "1"}, "secret.set", "store a secret at /x")
}

func TestDarwinPresenceSignatureVerified(t *testing.T) {
	k, sign := ecSigner(t)
	link := &fakeLink{sign: sign}
	if err := verifyAs("secure-enclave", staticKeys{501: &k.PublicKey}, link); err != nil {
		t.Fatalf("a valid signature = %v", err)
	}
	if len(link.got) != 1 || link.got[0].Action != "secret.set" || link.got[0].Summary != "store a secret at /x" || len(link.got[0].Nonce) != nonceLen {
		t.Fatalf("challenge = %+v", link.got)
	}
}

func TestDarwinPresenceMissingRefused(t *testing.T) {
	k, sign := ecSigner(t)
	for name, link := range map[string]HelperLink{
		"empty signature": &fakeLink{sign: func(Challenge) ([]byte, error) { return nil, nil }},
		"no helper":       &fakeLink{sign: func(Challenge) ([]byte, error) { return nil, ErrNoHelper }},
		"declined":        &fakeLink{sign: func(Challenge) ([]byte, error) { return nil, errors.New("presence declined: cancelled") }},
		"garbage":         &fakeLink{sign: func(Challenge) ([]byte, error) { return []byte("not a signature"), nil }},
		"other message": &fakeLink{sign: func(c Challenge) ([]byte, error) {
			c.Summary = "something else"
			return sign(c)
		}},
	} {
		if err := verifyAs("secure-enclave", staticKeys{501: &k.PublicKey}, link); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := verifyAs("secure-enclave", staticKeys{}, &fakeLink{sign: sign}); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("no registered key = %v", err)
	}
	if err := verifyAs("secure-enclave", staticKeys{501: &k.PublicKey}, &fakeLink{sign: func(Challenge) ([]byte, error) { return nil, ErrNoHelper }}); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("no helper must read as unavailable: %v", err)
	}
}

func TestWindowsPresenceSignatureVerified(t *testing.T) {
	k, sign := rsaSigner(t)
	if err := verifyAs("windows-hello", staticKeys{501: &k.PublicKey}, &fakeLink{sign: sign}); err != nil {
		t.Fatalf("a valid RSA signature = %v", err)
	}
}

func TestWindowsPresenceMissingRefused(t *testing.T) {
	k, sign := rsaSigner(t)
	other, otherSign := rsaSigner(t)
	_ = other
	if err := verifyAs("windows-hello", staticKeys{501: &k.PublicKey}, &fakeLink{sign: otherSign}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a signature by another key = %v", err)
	}
	if err := verifyAs("windows-hello", staticKeys{501: &k.PublicKey}, &fakeLink{sign: func(Challenge) ([]byte, error) { return nil, nil }}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an unsigned request = %v", err)
	}
	_ = sign
}

// A signature from an earlier challenge does not answer a new one.
func TestSignedPresenceReplayRefused(t *testing.T) {
	k, sign := ecSigner(t)
	var old []byte
	first := &fakeLink{sign: func(c Challenge) ([]byte, error) {
		s, err := sign(c)
		old = s
		return s, err
	}}
	if err := verifyAs("secure-enclave", staticKeys{501: &k.PublicKey}, first); err != nil {
		t.Fatal(err)
	}
	if err := verifyAs("secure-enclave", staticKeys{501: &k.PublicKey}, &fakeLink{sign: func(Challenge) ([]byte, error) { return old, nil }}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a replayed signature = %v", err)
	}
}

func TestPresenceKeyParsing(t *testing.T) {
	ec, _ := ecSigner(t)
	if _, err := ParsePresenceKey(pemOf(t, &ec.PublicKey)); err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, in := range map[string][]byte{
		"not pem":     []byte("nope"),
		"p384":        pemOf(t, &p384.PublicKey),
		"rsa1024":     pemOf(t, &small.PublicKey),
		"wrong block": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"bad der":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2}}),
	} {
		if _, err := ParsePresenceKey(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestDirKeysEnrollAndLookup(t *testing.T) {
	d := DirKeys{Dir: t.TempDir() + "/presence"}
	if _, err := d.PresenceKey(501); !errors.Is(err, ErrNoPresenceKey) {
		t.Fatalf("unenrolled = %v", err)
	}
	k, _ := ecSigner(t)
	if err := d.Enroll(501, []byte("junk")); err == nil {
		t.Fatal("a malformed key was enrolled")
	}
	if err := d.Enroll(501, pemOf(t, &k.PublicKey)); err != nil {
		t.Fatal(err)
	}
	got, err := d.PresenceKey(501)
	if err != nil || !got.(*ecdsa.PublicKey).Equal(&k.PublicKey) {
		t.Fatalf("lookup = %v, %v", got, err)
	}
	if _, err := d.PresenceKey(502); !errors.Is(err, ErrNoPresenceKey) {
		t.Fatalf("another user = %v", err)
	}
}

// helperSide answers challenges on the client end like the real helper.
func helperSide(t *testing.T, client pipeConn, sign func(Challenge) ([]byte, error), decline string) {
	t.Helper()
	go func() {
		sc := bufio.NewScanner(client)
		for sc.Scan() {
			var rq helperRequest
			if json.Unmarshal(sc.Bytes(), &rq) != nil {
				return
			}
			rep := helperReply{ID: rq.ID}
			if decline != "" {
				rep.Error = decline
			} else {
				rep.Signature, _ = sign(Challenge{Nonce: rq.Nonce, Action: rq.Action, Summary: rq.Summary})
			}
			b, _ := json.Marshal(rep)
			if _, err := client.Write(append(b, '\n')); err != nil {
				return
			}
		}
	}()
}

func TestHelperHubRoundTrip(t *testing.T) {
	hub := NewHelperHub()
	if _, err := hub.Sign(context.Background(), 501, Challenge{}); !errors.Is(err, ErrNoHelper) {
		t.Fatalf("no helper = %v", err)
	}
	k, sign := ecSigner(t)
	server, client := connPair()
	served := make(chan struct{})
	go func() { hub.Serve(501, server); close(served) }()
	helperSide(t, client, sign, "")
	for i := 0; !hub.Connected(501) && i < 200; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	p := &SignedPresence{Platform: "secure-enclave", Keys: staticKeys{501: &k.PublicKey}, Link: hub}
	if err := p.Verify(context.Background(), Subject{UID: 501}, "secret.set", "s"); err != nil {
		t.Fatalf("round trip = %v", err)
	}
	if err := p.Verify(context.Background(), Subject{UID: 501}, "secret.delete", "t"); err != nil {
		t.Fatalf("second round trip = %v", err)
	}
	_ = client.Close()
	<-served
	if hub.Connected(501) {
		t.Fatal("a closed helper stayed registered")
	}
}

func TestHelperHubDeclineAndReplace(t *testing.T) {
	hub := NewHelperHub()
	_, sign := ecSigner(t)
	s1, c1 := connPair()
	done1 := make(chan struct{})
	go func() { hub.Serve(501, s1); close(done1) }()
	helperSide(t, c1, sign, "cancelled")
	for i := 0; !hub.Connected(501) && i < 200; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := hub.Sign(context.Background(), 501, Challenge{}); err == nil {
		t.Fatal("a declined prompt returned a signature")
	}
	s2, c2 := connPair()
	go hub.Serve(501, s2)
	<-done1 // the first helper is closed by its replacement
	helperSide(t, c2, sign, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	silent, quiet := connPair()
	go hub.Serve(502, silent)
	for i := 0; !hub.Connected(502) && i < 200; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := hub.Sign(ctx, 502, Challenge{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a helper that never answers = %v", err)
	}
	_ = quiet.Close()
}
