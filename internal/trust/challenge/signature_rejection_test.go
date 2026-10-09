package challenge

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestBytesIncludesOptionalHashesSorted(t *testing.T) {
	c := Challenge{
		Actor: "a", Capability: "inject", Bind: BindFull, Nonce: "n",
		CommandHash: "ch", CwdHash: "wh",
		Exp: time.Date(2030, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600)),
	}
	want := `{"actor":"a","bind":"full","capability":"inject","command_hash":"ch","cwd_hash":"wh","exp":"2030-01-02T02:04:05.000000006Z","nonce":"n"}`
	if got := string(c.Bytes()); got != want {
		t.Fatalf("Bytes = %s\nwant    %s", got, want)
	}
	c.CommandHash = "other"
	if string(c.Bytes()) == want {
		t.Fatal("command hash not bound into canonical bytes")
	}
}

func TestVerifyRejectsWrongKeysAndSignatures(t *testing.T) {
	c := New("a", "inject", time.Minute)
	msg := c.Bytes()
	digest := sha256.Sum256(msg)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, []byte{0x30, 0}, &p384.PublicKey); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Errorf("P-384: %v", err)
	}

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, []byte("garbage"), &p256.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("bad DER: %v", err)
	}
	other := New("b", "inject", time.Minute)
	otherDigest := sha256.Sum256(other.Bytes())
	sig, err := ecdsa.SignASN1(rand.Reader, p256, otherDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, sig, &p256.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("ECDSA wrong message: %v", err)
	}
	sig, _ = ecdsa.SignASN1(rand.Reader, p256, digest[:])
	if err := Verify(c, sig, &p256.PublicKey); err != nil {
		t.Errorf("ECDSA valid: %v", err)
	}

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(c, make([]byte, 256), &rk.PublicKey); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("RSA bad sig: %v", err)
	}

	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(c, make([]byte, 64), edPub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("Ed25519 bad sig: %v", err)
	}
	if err := Verify(c, nil, "not-a-key"); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Errorf("unknown key: %v", err)
	}
}

func TestParseDERSig(t *testing.T) {
	cases := []struct {
		name string
		der  []byte
		ok   bool
		r, s int64
	}{
		{"valid", []byte{0x30, 6, 0x02, 1, 5, 0x02, 1, 7}, true, 5, 7},
		{"too short", []byte{0x30}, false, 0, 0},
		{"not a sequence", []byte{0x31, 6, 0x02, 1, 5, 0x02, 1, 7}, false, 0, 0},
		{"sequence length overflows", []byte{0x30, 9, 0x02, 1, 5}, false, 0, 0},
		{"r not integer", []byte{0x30, 6, 0x04, 1, 5, 0x02, 1, 7}, false, 0, 0},
		{"r length overflows", []byte{0x30, 3, 0x02, 5, 5}, false, 0, 0},
		{"s missing", []byte{0x30, 3, 0x02, 1, 5}, false, 0, 0},
		{"s not integer", []byte{0x30, 6, 0x02, 1, 5, 0x04, 1, 7}, false, 0, 0},
		{"s length overflows", []byte{0x30, 6, 0x02, 1, 5, 0x02, 4, 7}, false, 0, 0},
	}
	for _, tc := range cases {
		r, s := new(big.Int), new(big.Int)
		ok := parseDERSig(tc.der, r, s)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", tc.name, ok)
			continue
		}
		if ok && (r.Int64() != tc.r || s.Int64() != tc.s) {
			t.Errorf("%s: r=%v s=%v", tc.name, r, s)
		}
	}
}
