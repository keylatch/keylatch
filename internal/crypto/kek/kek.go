// Package kek defines the KEK (Key Encryption Key) interface and its sentinel
// errors. KEK providers wrap and unwrap DEK byte slices using algorithm-specific
// cryptographic material (passphrase+Argon2id, macOS Keychain, 1Password, etc.).
package kek

import "errors"

// KEK wraps and unwraps DEK byte slices.
//
// Implementations must be safe for concurrent use from multiple goroutines.
type KEK interface {
	// Wrap encrypts dek under this KEK. The returned bytes are safe to store on
	// disk alongside the keyring file.
	Wrap(dek []byte) (wrapped []byte, err error)

	// Unwrap decrypts wrapped to recover the original DEK bytes. Returns
	// ErrKEKUnavailable if the underlying credential source is inaccessible.
	Unwrap(wrapped []byte) (dek []byte, err error)

	// ID returns a stable, opaque string identifying this KEK instance (e.g.
	// a keychain item name, a 1Password item title). Used in the KeyringFile
	// to track which KEK wrapped each term.
	ID() string

	// Type returns the KEK provider type string. One of: "passphrase",
	// "keychain", "op", "bw", "age-env".
	Type() string
}

// Sentinel errors.
var (
	// ErrKEKUnavailable is returned by Unwrap when the underlying credential
	// source is inaccessible (e.g. CLI tool not found, item not in keychain,
	// biometric auth failed).
	ErrKEKUnavailable = errors.New("kek: KEK unavailable")

	// ErrKEKMismatch is returned when no term in the keyring file can be
	// unwrapped with the provided KEK.
	ErrKEKMismatch = errors.New("kek: no term decryptable with this KEK")
)
