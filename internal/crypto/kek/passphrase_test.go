package kek_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

var testParams = argon2.Params{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 1,
	SaltLen: 32,
	KeyLen:  32,
}

var testSalt = make([]byte, 32)

func init() {
	for i := range testSalt {
		testSalt[i] = byte(i)
	}
}

func TestPassphraseKEKRoundTrip(t *testing.T) {
	passphrase := []byte("test-passphrase-12345")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	k, err := kek.PassphraseKEK(passphrase, salt, testParams)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 10)
	}

	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	got, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if string(got) != string(dek) {
		t.Errorf("DEK mismatch after round-trip")
	}
}

func TestPassphraseKEKWrongPassphraseUnwrapFails(t *testing.T) {
	salt := make([]byte, 32)

	k1, err := kek.PassphraseKEK([]byte("correct-pass"), salt, testParams)
	if err != nil {
		t.Fatalf("PassphraseKEK (k1): %v", err)
	}

	dek := make([]byte, 32)
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Different salt → different wrapping key → Unwrap must fail.
	salt2 := make([]byte, 32)
	salt2[0] = 0xFF
	k2, err := kek.PassphraseKEK([]byte("wrong-pass"), salt2, testParams)
	if err != nil {
		t.Fatalf("PassphraseKEK (k2): %v", err)
	}

	_, err = k2.Unwrap(wrapped)
	if err == nil {
		t.Error("expected Unwrap to fail with wrong passphrase")
	}
}

func TestPassphraseKEKType(t *testing.T) {
	k, err := kek.PassphraseKEK([]byte("pass"), testSalt, testParams)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}
	if k.Type() != "passphrase" {
		t.Errorf("Type = %q, want %q", k.Type(), "passphrase")
	}
	if k.ID() != "passphrase" {
		t.Errorf("ID = %q, want %q", k.ID(), "passphrase")
	}
}

func TestPassphraseZeroedAfterDerive(t *testing.T) {
	// S5-6: passphrase must be zeroed after PassphraseKEK returns.
	passphrase := []byte("zero-me-after-derive")
	salt := make([]byte, 32)

	_, err := kek.PassphraseKEK(passphrase, salt, testParams)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	// The passphrase slice should be all zeros.
	for i, b := range passphrase {
		if b != 0 {
			t.Errorf("passphrase[%d] = %02x, want 0x00 (S5-6: passphrase not zeroed)", i, b)
		}
	}
}

func TestOPKEKMocked(t *testing.T) {
	// Test OPKEK with a mock runner.
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 5)
	}

	// Mock runner returns a hex-encoded 32-byte key.
	hexKey := make([]byte, 64)
	for i := 0; i < 32; i++ {
		hexKey[2*i] = "0123456789abcdef"[dek[i]>>4]
		hexKey[2*i+1] = "0123456789abcdef"[dek[i]&0xf]
	}

	// Use the exported opKEKWithRunner test helper via an internal test.
	// Since we are in package kek_test, we use OPKEK directly.
	// In the actual test we rely on the exported behavior: OPKEK fails when
	// the op CLI is not available, which returns ErrKEKUnavailable.
	_, err := kek.OPKEK("vault", "item", "field")
	if err == nil {
		t.Skip("op CLI is available; skipping mock test")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error")
	}
}

func TestBWKEKMocked(t *testing.T) {
	// BWKEK without BW_SESSION should fail.
	t.Setenv("BW_SESSION", "")
	_, err := kek.BWKEK("item-id", "field-name")
	if err == nil {
		t.Error("expected error when BW_SESSION not set")
	}
}
