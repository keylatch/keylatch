package keyops

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestJWSSignaturesRoundTrip(t *testing.T) {
	k := newTestKeys(t)
	for alg, key := range map[string][]byte{ES256: k.es256, ES384: k.es384} {
		sig, err := Sign(alg, key, []byte("m"), true)
		if err != nil {
			t.Fatal(err)
		}
		want := 64
		if alg == ES384 {
			want = 96
		}
		if len(sig) != want {
			t.Fatalf("%s raw signature is %d bytes", alg, len(sig))
		}
		if ok, err := Verify(alg, key, []byte("m"), sig, true); err != nil || !ok {
			t.Fatalf("%s: %v %v", alg, ok, err)
		}
		if ok, _ := Verify(alg, key, []byte("m"), sig[:len(sig)-1], true); ok {
			t.Fatalf("%s: a truncated signature verified", alg)
		}
		if ok, _ := Verify(alg, key, []byte("x"), sig, true); ok {
			t.Fatalf("%s: a signature over other input verified", alg)
		}
	}
}

func TestKeyParsingFormats(t *testing.T) {
	k := newTestKeys(t)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	openssh, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(EdDSA, pem.EncodeToMemory(openssh), []byte("m"), false)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("OpenSSH ed25519 key: %v", err)
	}
	if _, err := Sign(RS256, k.rsaKey, []byte("m"), false); err != nil {
		t.Fatal(err)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallPEM := pkcs8PEM(t, small)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	for name, tc := range map[string]struct {
		alg string
		key []byte
	}{
		"not PEM":         {EdDSA, []byte("raw bytes")},
		"garbage PEM":     {EdDSA, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")},
		"small RSA":       {RS256, smallPEM},
		"wrong family":    {EdDSA, k.rsaKey},
		"wrong curve":     {ES256, k.es384},
		"P-521":           {ES384, pkcs8PEM(t, p521)},
		"rsa for ecdsa":   {ES256, k.rsaKey},
		"ed25519 for rsa": {PS256, k.ed},
		"empty hmac key":  {HS256, nil},
		"unsupported alg": {"none", k.ed},
	} {
		if _, err := Sign(tc.alg, tc.key, []byte("m"), false); err == nil {
			t.Errorf("%s: signed", name)
		}
		if _, err := Verify(tc.alg, tc.key, []byte("m"), []byte("s"), false); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestAESKeyAndCiphertextErrors(t *testing.T) {
	k := newTestKeys(t)
	if _, err := Encrypt([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("a short key encrypted")
	}
	if _, err := Decrypt([]byte("short"), make([]byte, 40), nil); err == nil {
		t.Fatal("a short key decrypted")
	}
	if _, err := Decrypt(k.aes, []byte("tiny"), nil); err == nil || !strings.Contains(err.Error(), "short") {
		t.Fatalf("short ciphertext: %v", err)
	}
	ct, _ := Encrypt(k.aes, []byte("x"), nil)
	ct[len(ct)-1] ^= 1
	if _, err := Decrypt(k.aes, ct, nil); err == nil {
		t.Fatal("a modified ciphertext decrypted")
	}
	other := make([]byte, 32)
	ct, _ = Encrypt(k.aes, []byte("x"), nil)
	if _, err := Decrypt(other, ct, nil); err == nil {
		t.Fatal("the wrong key decrypted")
	}
}

func TestJWTErrors(t *testing.T) {
	k := newTestKeys(t)
	if _, err := SignJWT(RS256, k.rsaKey, []byte("{}"), ""); err == nil {
		t.Fatal("RS256 is not a permitted JWT algorithm")
	}
	if _, err := SignJWT(HS256, nil, []byte("{}"), ""); err == nil {
		t.Fatal("an empty key signed a JWT")
	}
}

func TestOperationAlgorithmFit(t *testing.T) {
	for _, tc := range []struct {
		op   Operation
		alg  string
		want bool
	}{
		{OpSign, PS256, true}, {OpVerify, HS512, true}, {OpEncrypt, A256GCM, true}, {OpDecrypt, HS256, false},
		{OpJWTSign, ES256, true}, {OpJWTSign, PS256, false}, {OpSSHSign, EdDSA, false}, {OpSign, A256GCM, false},
	} {
		if got := algorithmFits(tc.op, tc.alg); got != tc.want {
			t.Errorf("%s/%s = %v", tc.op, tc.alg, got)
		}
	}
	if newHash("nope") != nil {
		t.Error("unknown algorithm has a hash")
	}
}

func TestServiceInputValidation(t *testing.T) {
	k := newTestKeys(t)
	s, _ := service(t, fullPolicy("k", []string{"sign", "encrypt"}, HS256, A256GCM), mapKeys{"k": k.hmac})
	ctx := context.Background()
	for name, req := range map[string]Request{
		"unknown operation": {Operation: "export", Connection: "app-local"},
		"no connection":     {Operation: OpSign},
		"oversized input":   {Operation: OpSign, Connection: "app-local", Alg: HS256, Input: make([]byte, MaxInput+1)},
		"alg needed":        {Operation: OpSign, Connection: "app-local", Input: []byte("x")},
	} {
		_, err := s.Do(ctx, human, req)
		if name == "alg needed" {
			// one signing algorithm is allowed, so it is the default
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	two := fullPolicy("k", []string{"sign"}, HS256, HS512)
	s2, _ := service(t, two, mapKeys{"k": k.hmac})
	if _, err := s2.Do(ctx, human, Request{Operation: OpSign, Connection: "app-local", Input: []byte("x")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ambiguous algorithm: %v", err)
	}
	s3, _ := service(t, fullPolicy("missing", []string{"sign"}, HS256), mapKeys{})
	if _, err := s3.Do(ctx, human, Request{Operation: OpSign, Connection: "app-local", Input: []byte("x")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a key missing from the backend: %v", err)
	}
	if _, err := s.Do(ctx, human, Request{Operation: OpEncrypt, Connection: "app-local", Alg: A256GCM, Input: []byte("x")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an HMAC key used for AES: %v", err)
	}
}

func TestBackendKeysReportsUnavailableBackend(t *testing.T) {
	cfg := config.Default()
	cfg.Backend = "no-such-backend"
	_, err := NewBackendKeys(cfg, func(string) string { return "" }).Fetch(context.Background(), "p")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
}

func TestSSHAgentDirectMethods(t *testing.T) {
	k := newTestKeys(t)
	s, cap := service(t, sshPolicy(), mapKeys{"k": k.ed})
	a := s.NewSSHAgent(Caller{Kind: "agent", Constrained: true})

	keys, err := a.List()
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	pub, _ := ssh.ParsePublicKey(keys[0].Blob)
	sig, err := a.Sign(pub, []byte("d"))
	if err != nil || pub.Verify([]byte("d"), sig) != nil {
		t.Fatalf("sign: %v", err)
	}
	for name, err := range map[string]error{
		"lock": a.Lock(nil), "unlock": a.Unlock(nil), "add": a.Add(agent.AddedKey{}), "remove": a.Remove(pub), "remove all": a.RemoveAll(),
	} {
		if err == nil {
			t.Errorf("%s was allowed", name)
		}
	}
	if s, err := a.Signers(); err == nil || s != nil {
		t.Error("signers were handed out")
	}
	if _, err := a.Extension("query", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("other extensions: %v", err)
	}
	if _, err := a.Extension(sessionBindExtension, []byte("garbage")); err == nil {
		t.Error("a malformed session-bind was accepted")
	}
	if !strings.Contains(cap.dump(), `"operation":"ssh_sign"`) {
		t.Fatal("not audited")
	}
}

func TestSSHAgentSkipsUnusableKeysAndFailsClosedOnAudit(t *testing.T) {
	k := newTestKeys(t)
	p := staticPolicy{conns: map[string]map[string]FieldPolicy{
		"a": {"GOOD": {Secret: "good", SSHAgent: &SSHPolicy{}}, "MISSING": {Secret: "absent", SSHAgent: &SSHPolicy{}}, "BAD": {Secret: "bad", SSHAgent: &SSHPolicy{}}},
	}}
	s, cap := service(t, p, mapKeys{"good": k.ed, "bad": []byte("not a key")})
	a := s.NewSSHAgent(human)
	keys, err := a.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("unusable keys were listed: %v %v", keys, err)
	}
	pub, _ := ssh.ParsePublicKey(keys[0].Blob)
	cap.fail = true
	if _, err := a.Sign(pub, []byte("d")); err == nil {
		t.Fatal("a signature was returned although the audit log is unwritable")
	}
}

func TestSSHKeysListedInOrder(t *testing.T) {
	s, a, _ := seeded(t)
	ctx := context.Background()
	_ = a.Allow(ctx, human, Change{Connection: "b", Field: "K", Secret: "s", SSHAgent: true})
	_ = a.Allow(ctx, human, Change{Connection: "a", Field: "K2", Secret: "s", SSHAgent: true, HostKeys: []string{"SHA256:x"}})
	_ = a.Allow(ctx, human, Change{Connection: "a", Field: "K1", Secret: "s", SSHAgent: true})
	keys, err := s.SSHKeys()
	if err != nil || len(keys) != 3 || keys[0].Field != "K1" || keys[1].Field != "K2" || keys[2].Connection != "b" {
		t.Fatalf("ssh keys: %+v %v", keys, err)
	}
}
