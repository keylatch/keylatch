// Package envelope provides the AEAD Seal/Open primitives used by the keylatch
// credential store. It supports XChaCha20-Poly1305 and AES-256-GCM.
//
// Security invariants (Phase 5):
//   - S5-4: Open returns ErrAEADAuthFailed for ALL authentication failures —
//     uniform oracle, no distinguishing information in the error string.
//   - XChaCha20 nonces are always random (24 bytes from crypto/rand).
//   - AES-GCM nonces are always provided by the caller via NonceProvider (never
//     generated randomly inside this package).
package envelope

import "errors"

// Algorithm identifies an AEAD algorithm supported by this package.
type Algorithm string

const (
	// XChaCha20Poly1305 is the default algorithm. 24-byte random nonce,
	// 32-byte DEK, authenticated ciphertext with Poly1305 tag.
	XChaCha20Poly1305 Algorithm = "xchacha20-poly1305"

	// AES256GCM is the FIPS-compliant algorithm. 12-byte monotonic nonce
	// supplied by the caller's NonceProvider, 32-byte DEK.
	AES256GCM Algorithm = "aes-256-gcm"
)

// NonceLen returns the nonce length in bytes for alg.
// Returns -1 for unknown algorithms.
func NonceLen(alg Algorithm) int {
	switch alg {
	case XChaCha20Poly1305:
		return 24
	case AES256GCM:
		return 12
	default:
		return -1
	}
}

// NonceProvider supplies nonces for AES-GCM encryption. Implementations must
// guarantee monotonic uniqueness across process restarts and concurrent callers
// (see keyring.NextGCMNonce for the reference implementation with flock-based
// inter-process locking).
//
// It is NOT used for XChaCha20-Poly1305, which derives nonces from crypto/rand.
type NonceProvider interface {
	// Next returns a fresh nonce for the given algorithm and key term.
	// For AES-GCM the returned slice must be exactly 12 bytes.
	Next(alg Algorithm, term int) ([]byte, error)
}

// Sentinel errors returned by Seal and Open.
var (
	// ErrAEADAuthFailed is returned by Open for all authentication failure
	// modes: wrong AAD, wrong DEK, wrong nonce, tampered ciphertext, truncated
	// ciphertext. No distinguishing information is included (S5-4).
	ErrAEADAuthFailed = errors.New("envelope: AEAD authentication failed")

	// ErrAlgorithmUnknown is returned when the Algorithm value is not one of
	// the registered constants.
	ErrAlgorithmUnknown = errors.New("envelope: unknown algorithm")
)
