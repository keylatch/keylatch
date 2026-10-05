// Package protonpass implements the Proton Pass backend for keylatch.
// Versioned storage is not supported; all versioned/metadata methods return ErrNotSupported.
package protonpass

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// GetMeta returns ErrNotSupported — Proton Pass does not support versioned metadata.
func (b *ProtonPassBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

// SetMeta returns ErrNotSupported.
func (b *ProtonPassBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta returns ErrNotSupported.
func (b *ProtonPassBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned returns ErrNotSupported.
func (b *ProtonPassBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned returns ErrNotSupported.
func (b *ProtonPassBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned returns ErrNotSupported.
func (b *ProtonPassBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// ID returns the Proton Pass backend stable identifier.
func (b *ProtonPassBackend) ID() string {
	if b.opts.Vault != "" {
		return "proton-pass:" + b.opts.Vault
	}
	return "proton-pass:default"
}
