package envelope

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// SealXChaCha20 encrypts plaintext with XChaCha20-Poly1305 using a fresh
// 24-byte random nonce from crypto/rand.
//
// dek must be exactly 32 bytes. aad is the associated data bound into the tag.
//
// Returns (ciphertext, nonce, error). The ciphertext includes the Poly1305 tag.
func SealXChaCha20(dek, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	if len(dek) != chacha20poly1305.KeySize {
		return nil, nil, fmt.Errorf("%w: XChaCha20 DEK must be 32 bytes, got %d", ErrAlgorithmUnknown, len(dek))
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: create XChaCha20 AEAD: %w", err)
	}

	nonce = make([]byte, aead.NonceSize()) // 24 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("envelope: generate nonce: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}
