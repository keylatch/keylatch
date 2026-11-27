package testutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// aeadKEK is a KEK backed by a random AES-256-GCM key, for tests that need to
// seal something without a keyring, a keychain or a passphrase prompt.
type aeadKEK struct{ aead cipher.AEAD }

var _ kek.KEK = aeadKEK{}

// NewKEK returns a KEK that wraps with a fresh random key.
func NewKEK(t testing.TB) kek.KEK {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("testutil: random key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("testutil: cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("testutil: gcm: %v", err)
	}
	return aeadKEK{aead: aead}
}

func (k aeadKEK) Wrap(plain []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plain, nil), nil
}

func (k aeadKEK) Unwrap(wrapped []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(wrapped) < n {
		return nil, errors.New("testutil: wrapped value is too short")
	}
	return k.aead.Open(nil, wrapped[:n], wrapped[n:], nil)
}

func (aeadKEK) ID() string   { return "testutil-aead" }
func (aeadKEK) Type() string { return "passphrase" }
