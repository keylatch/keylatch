package challenge_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/trust/challenge"
)

func TestNew(t *testing.T) {
	c := challenge.New("alice", "inject", 5*time.Minute)
	if c.Actor != "alice" {
		t.Errorf("Actor = %q, want %q", c.Actor, "alice")
	}
	if c.Capability != "inject" {
		t.Errorf("Capability = %q, want %q", c.Capability, "inject")
	}
	if c.Nonce == "" {
		t.Error("Nonce is empty")
	}
	if c.Exp.Before(time.Now()) {
		t.Error("Exp is in the past immediately after creation")
	}
}

func TestBytes_Determinism(t *testing.T) {
	c := challenge.Challenge{
		Actor:      "alice",
		Capability: "inject",
		Exp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Bind:       challenge.BindNone,
		Nonce:      "deadbeef",
	}
	b1 := c.Bytes()
	b2 := c.Bytes()
	if string(b1) != string(b2) {
		t.Errorf("Bytes() is not deterministic:\n  call1: %s\n  call2: %s", b1, b2)
	}
}

func TestVerify_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := challenge.New("alice", "inject", 5*time.Minute)
	sig := ed25519.Sign(priv, c.Bytes())

	if err := challenge.Verify(c, sig, pub); err != nil {
		t.Errorf("Verify(Ed25519) unexpected error: %v", err)
	}
}

func TestVerify_ECDSAP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := challenge.New("alice", "inject", 5*time.Minute)
	h := sha256.Sum256(c.Bytes())
	der, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := challenge.Verify(c, der, &priv.PublicKey); err != nil {
		t.Errorf("Verify(ECDSA P-256) unexpected error: %v", err)
	}
}

func TestVerify_RSAPSS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := challenge.New("alice", "inject", 5*time.Minute)
	h := sha256.Sum256(c.Bytes())
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	if err := challenge.Verify(c, sig, &priv.PublicKey); err != nil {
		t.Errorf("Verify(RSA-PSS) unexpected error: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := challenge.New("alice", "inject", 5*time.Minute)
	sig := ed25519.Sign(priv, c.Bytes())
	// Tamper with one byte.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xff
	if err := challenge.Verify(c, tampered, pub); err == nil {
		t.Error("Verify with tampered sig: expected error, got nil")
	}
}

func TestVerify_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := challenge.Challenge{
		Actor:      "alice",
		Capability: "inject",
		Exp:        time.Now().UTC().Add(-1 * time.Second), // already expired
		Bind:       challenge.BindNone,
		Nonce:      "deadbeef",
	}
	sig := ed25519.Sign(priv, c.Bytes())
	err := challenge.Verify(c, sig, pub)
	if err != challenge.ErrChallengeExpired {
		t.Errorf("Verify expired: want ErrChallengeExpired, got %v", err)
	}
}
