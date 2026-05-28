// Package op implements the 1Password backend for keylatch.
// Phase 4 stubs: versioned storage is not supported; all Phase 4 methods return ErrNotSupported.
package op

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// GetMeta returns ErrNotSupported — 1Password does not support Phase 4 metadata.
func (b *OnePasswordBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

// SetMeta returns ErrNotSupported.
func (b *OnePasswordBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta returns ErrNotSupported.
func (b *OnePasswordBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned returns ErrNotSupported.
func (b *OnePasswordBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned returns ErrNotSupported.
func (b *OnePasswordBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned returns ErrNotSupported.
func (b *OnePasswordBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// ID returns the 1Password backend stable identifier.
func (b *OnePasswordBackend) ID() string { return "op:" + b.opts.Vault }
