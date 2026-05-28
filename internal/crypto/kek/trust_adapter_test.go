package kek_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/trust"
)

func makePassphraseAdapter(t *testing.T) trust.RootOfTrust {
	t.Helper()
	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte("test-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}
	return kek.AsRootOfTrust(k)
}

func TestKEKAdapter_HasCapWrap(t *testing.T) {
	a := makePassphraseAdapter(t)
	if !a.Has(trust.CapWrap) {
		t.Error("Has(CapWrap) = false, want true")
	}
}

func TestKEKAdapter_HasCapSignChallenge_False(t *testing.T) {
	a := makePassphraseAdapter(t)
	if a.Has(trust.CapSignChallenge) {
		t.Error("Has(CapSignChallenge) = true, want false")
	}
	if a.Has(trust.CapUserPresence) {
		t.Error("Has(CapUserPresence) = true, want false")
	}
	if a.Has(trust.CapHardwareBound) {
		t.Error("Has(CapHardwareBound) = true, want false")
	}
}

func TestKEKAdapter_WrapUnwrapRoundTrip(t *testing.T) {
	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}

	k1, err := kek.PassphraseKEK([]byte("roundtrip"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK(1): %v", err)
	}
	a1 := kek.AsRootOfTrust(k1)

	dek := []byte("this-is-a-32-byte-dek-padded!!!!") // 32 bytes

	// Save the expected plaintext before Wrap zeroes dek in place (S11-1
	// security requirement: Wrap zeros the caller's dek slice via defer).
	wantDEK := string(dek)

	wrapped, err := a1.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Need new KEK since passphrase was zeroed.
	k2, err := kek.PassphraseKEK([]byte("roundtrip"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK(2): %v", err)
	}
	a2 := kek.AsRootOfTrust(k2)

	recovered, err := a2.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(recovered) != wantDEK {
		t.Errorf("recovered DEK mismatch: got %q, want %q", recovered, wantDEK)
	}
}

func TestKEKAdapter_SignReturnsErrCapabilityUnsupported(t *testing.T) {
	a := makePassphraseAdapter(t)
	_, _, err := a.Sign(context.Background(), []byte("challenge"))
	if err != trust.ErrCapabilityUnsupported {
		t.Errorf("Sign: want ErrCapabilityUnsupported, got %v", err)
	}
}

func TestKEKAdapter_Type(t *testing.T) {
	a := makePassphraseAdapter(t)
	if a.Type() != trust.RootPassphrase {
		t.Errorf("Type() = %q, want %q", a.Type(), trust.RootPassphrase)
	}
}

func TestKEKAdapter_Close(t *testing.T) {
	a := makePassphraseAdapter(t)
	if err := a.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
