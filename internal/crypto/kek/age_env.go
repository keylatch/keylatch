//go:build !fips

package kek

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/crypto/hkdf"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// ageEnvKEK implements KEK using an age X25519 identity file pointed to by
// the KEYLATCH_AGE_IDENTITY environment variable.
type ageEnvKEK struct {
	wrappingKey []byte
	salt        []byte
}

// EnvAgeIdentityKEK reads an age identity from the path in $KEYLATCH_AGE_IDENTITY,
// enforces mode 0o600, and derives a 32-byte wrapping key via HKDF-SHA256.
//
// The salt parameter should be KeyringFile.Salt so the derived key is bound to
// the keyring.
//
// Build tag: !fips (age is excluded from FIPS builds).
func EnvAgeIdentityKEK(salt []byte) (KEK, error) {
	identityPath := os.Getenv("KEYLATCH_AGE_IDENTITY")
	if identityPath == "" {
		return nil, fmt.Errorf("%w: KEYLATCH_AGE_IDENTITY not set", ErrKEKUnavailable)
	}
	return AgeIdentityKEKFromPath(identityPath, salt)
}

// AgeIdentityKEKFromPath reads an age identity file from the given path,
// enforces mode 0o600, and derives a 32-byte wrapping key via HKDF-SHA256.
//
// This is the underlying implementation of EnvAgeIdentityKEK, exposed so
// callers (e.g. the file backend factory's loadPlatformKEK) can specify an
// explicit path — for example, the well-known bootstrap identity path — when
// the KEYLATCH_AGE_IDENTITY env var is not set.
//
// The salt parameter should be KeyringFile.Salt so the derived key is bound to
// the keyring.
//
// Build tag: !fips (age is excluded from FIPS builds).
func AgeIdentityKEKFromPath(identityPath string, salt []byte) (KEK, error) {
	if identityPath == "" {
		return nil, fmt.Errorf("%w: identity path is empty", ErrKEKUnavailable)
	}

	info, err := os.Stat(identityPath) //nolint:gosec // G703: path comes from operator-controlled env var or config; not user input
	if err != nil {
		return nil, fmt.Errorf("%w: stat %q: %v", ErrKEKUnavailable, identityPath, err)
	}
	// Windows does not support Unix permission bits; skip the check there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: %q has mode %04o, want 0600", ErrKEKUnavailable, identityPath, info.Mode().Perm())
	}

	identityBytes, err := os.ReadFile(identityPath) //nolint:gosec // G703: path comes from operator-controlled source; path validation above confirms it exists and has 0600 permissions
	if err != nil {
		return nil, fmt.Errorf("%w: read %q: %v", ErrKEKUnavailable, identityPath, err)
	}

	// Derive 32 bytes via HKDF-SHA256.
	// info string: "keylatch/kek/v1"
	hkdfReader := hkdf.New(sha256.New, identityBytes, salt, []byte("keylatch/kek/v1"))
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, wrappingKey); err != nil {
		return nil, fmt.Errorf("kek: age-env HKDF: %w", err)
	}

	return &ageEnvKEK{wrappingKey: wrappingKey, salt: salt}, nil
}

// Wrap encrypts dek using XChaCha20-Poly1305 keyed by the HKDF-derived key.
func (k *ageEnvKEK) Wrap(dek []byte) ([]byte, error) {
	ct, nonce, err := envelope.SealXChaCha20(k.wrappingKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("kek: age-env wrap: %w", err)
	}
	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (k *ageEnvKEK) Unwrap(wrapped []byte) ([]byte, error) {
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

// ID returns the age identity path.
func (k *ageEnvKEK) ID() string { return "age-env:" + os.Getenv("KEYLATCH_AGE_IDENTITY") }

// Type returns the KEK provider type.
func (k *ageEnvKEK) Type() string { return "age-env" }
