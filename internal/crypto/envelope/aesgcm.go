package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// SealAESGCM encrypts plaintext with AES-256-GCM.
//
// The nonce MUST be supplied by the caller via np.Next(AES256GCM, term).
// This function NEVER generates a random nonce — for AES-GCM nonce uniqueness
// is enforced by the monotonic counter in the keyring (S5-FIND3-002).
//
// dek must be exactly 32 bytes; the nonce returned by np must be exactly 12 bytes.
func SealAESGCM(dek, plaintext, aad []byte, np NonceProvider, term int) (ciphertext, nonce []byte, err error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("%w: AES-256-GCM DEK must be 32 bytes, got %d", ErrAlgorithmUnknown, len(dek))
	}

	nonce, err = np.Next(AES256GCM, term)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: get GCM nonce: %w", err)
	}
	if len(nonce) != 12 {
		return nil, nil, fmt.Errorf("envelope: AES-GCM nonce must be 12 bytes, got %d", len(nonce))
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: create GCM: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}
