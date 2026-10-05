// Package lastpass implements the LastPass backend for keylatch.
// Versioned storage is not supported; all versioned/metadata methods return ErrNotSupported.
package lastpass

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// GetMeta returns ErrNotSupported — LastPass does not support versioned metadata.
func (b *LastPassBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

// SetMeta returns ErrNotSupported.
func (b *LastPassBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta returns ErrNotSupported.
func (b *LastPassBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned returns ErrNotSupported.
func (b *LastPassBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned returns ErrNotSupported.
func (b *LastPassBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned returns ErrNotSupported.
func (b *LastPassBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// ID returns the LastPass backend stable identifier with a hashed username.
// The raw username is never included to avoid leaking PII in logs.
func (b *LastPassBackend) ID() string {
	return "lastpass:" + hashUsername(b.opts.Username)
}

// hashUsername returns the first 16 hex characters of the SHA-256 of the username.
func hashUsername(username string) string {
	h := sha256.Sum256([]byte(username))
	return fmt.Sprintf("%x", h)[:16]
}
