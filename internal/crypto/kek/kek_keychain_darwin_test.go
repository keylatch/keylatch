//go:build darwin

package kek

// kek_keychain_darwin_test.go covers keychainKEKWithRunner, which is only
// compiled on darwin (keychain_darwin.go).

import (
	"errors"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// keychainKEKWithRunner (darwin build tag means it's compiled on darwin)
// ---------------------------------------------------------------------------

func TestKeychainKEKWithRunner_RunnerFails(t *testing.T) {
	t.Parallel()
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("security command not found")
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestKeychainKEKWithRunner_ShortHex(t *testing.T) {
	t.Parallel()
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte("tooshort"), nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for short hex, got %v", err)
	}
}

func TestKeychainKEKWithRunner_InvalidHex(t *testing.T) {
	t.Parallel()
	// 64 chars of invalid hex.
	_, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		invalid := make([]byte, 64)
		for i := range invalid {
			invalid[i] = 'z'
		}
		return invalid, nil
	})
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for invalid hex, got %v", err)
	}
}

func TestKeychainKEKWithRunner_ValidRoundTrip(t *testing.T) {
	t.Parallel()
	// Build a valid 64-char hex key.
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i + 3)
	}
	hexKey := fmt.Sprintf("%x\n", rawKey)

	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}

	if k.ID() != "test-item" {
		t.Errorf("ID = %q, want %q", k.ID(), "test-item")
	}
	if k.Type() != "keychain" {
		t.Errorf("Type = %q, want keychain", k.Type())
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 13)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	recovered, err := k.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(recovered) != string(dek) {
		t.Error("DEK mismatch after round-trip")
	}
}

func TestKeychainKEKWithRunner_Unwrap_TooShort(t *testing.T) {
	t.Parallel()
	rawKey := make([]byte, 32)
	hexKey := fmt.Sprintf("%x\n", rawKey)
	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}
	_, err = k.Unwrap([]byte("short"))
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable, got %v", err)
	}
}

func TestKeychainKEKWithRunner_Unwrap_Corrupted(t *testing.T) {
	t.Parallel()
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i + 17)
	}
	hexKey := fmt.Sprintf("%x\n", rawKey)
	k, err := keychainKEKWithRunner("test-item", func(_ string, _ ...string) ([]byte, error) {
		return []byte(hexKey), nil
	})
	if err != nil {
		t.Fatalf("keychainKEKWithRunner: %v", err)
	}
	dek := make([]byte, 32)
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0xff
	_, err = k.Unwrap(wrapped)
	if !errors.Is(err, ErrKEKUnavailable) {
		t.Errorf("expected ErrKEKUnavailable for corrupted blob, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// PassphraseKEK — derive error (KeyLen == 0)
// ---------------------------------------------------------------------------
