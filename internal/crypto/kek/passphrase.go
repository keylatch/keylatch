package kek

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// passphraseKEK implements KEK using Argon2id key derivation and
// XChaCha20-Poly1305 for wrap/unwrap.
type passphraseKEK struct {
	wrappingKey []byte // 32-byte Argon2id-derived key
}

// PassphraseKEK derives a wrapping key from passphrase+salt+params and returns
// a KEK backed by that key.
//
// S5-6: passphrase is zeroed immediately after Argon2id derivation.
func PassphraseKEK(passphrase, salt []byte, p argon2.Params) (KEK, error) {
	key, err := argon2.Derive(passphrase, salt, p)

	// Zero passphrase immediately, regardless of derive success.
	for i := range passphrase {
		passphrase[i] = 0
	}

	if err != nil {
		return nil, fmt.Errorf("kek: derive passphrase key: %w", err)
	}

	return &passphraseKEK{wrappingKey: key}, nil
}

// Wrap encrypts dek using XChaCha20-Poly1305 keyed by the Argon2id-derived key.
func (k *passphraseKEK) Wrap(dek []byte) ([]byte, error) {
	ct, nonce, err := envelope.SealXChaCha20(k.wrappingKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("kek: wrap: %w", err)
	}
	// Prepend the 24-byte nonce so the wrapped blob is self-contained.
	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (k *passphraseKEK) Unwrap(wrapped []byte) ([]byte, error) {
	const nonceLen = 24
	if len(wrapped) < nonceLen {
		return nil, ErrKEKUnavailable
	}
	nonce := wrapped[:nonceLen]
	ct := wrapped[nonceLen:]

	dek, err := envelope.Open(envelope.XChaCha20Poly1305, k.wrappingKey, ct, nonce, nil)
	if err != nil {
		return nil, ErrKEKUnavailable
	}
	return dek, nil
}

// ID returns a fixed identifier for passphrase KEK instances.
func (k *passphraseKEK) ID() string { return "passphrase" }

// Type returns the KEK provider type.
func (k *passphraseKEK) Type() string { return "passphrase" }
