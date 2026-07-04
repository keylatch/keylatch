package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Open decrypts and authenticates ciphertext using the specified algorithm.
//
// Security invariant: ALL authentication failure modes return the single
// sentinel ErrAEADAuthFailed — wrong AAD, wrong DEK, wrong nonce, tampered
// ciphertext, truncated ciphertext. No distinguishing information is included
// in the error message beyond the sentinel itself.
//
// Returns ErrAlgorithmUnknown if alg is not a registered constant.
func Open(alg Algorithm, dek, ciphertext, nonce, aad []byte) ([]byte, error) {
	switch alg {
	case XChaCha20Poly1305:
		return openXChaCha20(dek, ciphertext, nonce, aad)
	case AES256GCM:
		return openAESGCM(dek, ciphertext, nonce, aad)
	default:
		return nil, ErrAlgorithmUnknown
	}
}

// Seal encrypts plaintext with the given algorithm.
//
// For XChaCha20Poly1305: np and term are ignored; a fresh random nonce is
// generated internally.
// For AES256GCM: np.Next(AES256GCM, term) provides the nonce — it is NEVER
// generated randomly.
func Seal(alg Algorithm, dek, plaintext, aad []byte, np NonceProvider, term int) (ciphertext, nonce []byte, err error) {
	switch alg {
	case XChaCha20Poly1305:
		return SealXChaCha20(dek, plaintext, aad)
	case AES256GCM:
		return SealAESGCM(dek, plaintext, aad, np, term)
	default:
		return nil, nil, ErrAlgorithmUnknown
	}
}

// openXChaCha20 decrypts using XChaCha20-Poly1305.
func openXChaCha20(dek, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(dek) != chacha20poly1305.KeySize {
		// Uniform oracle: DEK length error maps to auth failure.
		return nil, ErrAEADAuthFailed
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Do not wrap — uniform oracle.
		return nil, ErrAEADAuthFailed
	}
	return plaintext, nil
}

// openAESGCM decrypts using AES-256-GCM.
func openAESGCM(dek, ciphertext, nonce, aad []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, ErrAEADAuthFailed
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}
	return plaintext, nil
}

// SealXChaChaWithNonce is a testing helper that seals with a caller-supplied
// nonce (used in KAT tests only). Not for production use.
func SealXChaChaWithNonce(dek, plaintext, nonce, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: create AEAD: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}
