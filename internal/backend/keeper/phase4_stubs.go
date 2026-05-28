// Package keeper implements the Keeper Commander backend for keylatch.
// Phase 4 stubs: versioned storage is not supported; all Phase 4 methods return ErrNotSupported.
package keeper

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// GetMeta returns ErrNotSupported — Keeper does not support Phase 4 metadata.
func (b *KeeperBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

// SetMeta returns ErrNotSupported.
func (b *KeeperBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta returns ErrNotSupported.
func (b *KeeperBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned returns ErrNotSupported.
func (b *KeeperBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned returns ErrNotSupported.
func (b *KeeperBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned returns ErrNotSupported.
func (b *KeeperBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// ID returns the Keeper backend stable identifier.
func (b *KeeperBackend) ID() string {
	if b.opts.AccountUID != "" {
		return "keeper:" + b.opts.AccountUID
	}
	return "keeper:default"
}
