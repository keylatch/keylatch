//go:build darwin

// Package keychain implements the macOS Keychain backend for keylatch.
// Phase 4 stubs: versioned storage is not supported; all Phase 4 methods return ErrNotSupported.
package keychain

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// GetMeta returns ErrNotSupported — Keychain does not support Phase 4 metadata.
func (k *KeychainBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

// SetMeta returns ErrNotSupported.
func (k *KeychainBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta returns ErrNotSupported.
func (k *KeychainBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned returns ErrNotSupported.
func (k *KeychainBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned returns ErrNotSupported.
func (k *KeychainBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned returns ErrNotSupported.
func (k *KeychainBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// ID returns the keychain backend stable identifier.
func (k *KeychainBackend) ID() string { return "keychain:" + k.opts.KeychainPath }
