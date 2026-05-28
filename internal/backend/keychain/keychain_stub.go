//go:build !darwin

// Package keychain implements the macOS Keychain backend.
// On non-darwin platforms, all methods return backend.ErrUnavailable.
package keychain

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// Options configures a KeychainBackend (stub for non-darwin).
type Options struct {
	KeychainPath string
	LockPath     string
	SecurityBin  string
	Runner       kexec.CommandRunner
	Env          llmcontext.Lookup
}

// KeychainBackend is the non-darwin stub.
type KeychainBackend struct{}

// Manifest is the non-darwin stub.
type Manifest struct {
	Version int
	Items   []ManifestRow
}

// ManifestRow is the non-darwin stub.
type ManifestRow struct {
	Connection string
	Account    string
	Fields     []string
}

// Open returns ErrUnavailable on non-darwin platforms.
func Open(_ Options) (*KeychainBackend, error) {
	return nil, backend.ErrUnavailable
}

// Name returns "keychain".
func (k *KeychainBackend) Name() string { return "keychain" }

// Capabilities returns an empty slice.
func (k *KeychainBackend) Capabilities() []backend.Capability { return nil }

// Get returns ErrUnavailable.
func (k *KeychainBackend) Get(_ context.Context, _ string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, backend.ErrUnavailable
}

// Set returns ErrUnavailable.
func (k *KeychainBackend) Set(_ context.Context, _ string, _ []byte, _ backend.Meta) error {
	return backend.ErrUnavailable
}

// Delete returns ErrUnavailable.
func (k *KeychainBackend) Delete(_ context.Context, _ string) error {
	return backend.ErrUnavailable
}

// List returns ErrUnavailable.
func (k *KeychainBackend) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, backend.ErrUnavailable
}

// GetMeta returns ErrNotSupported (Phase 4 versioned storage not available on non-file backends).
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

// ID returns the keychain backend identifier.
func (k *KeychainBackend) ID() string { return "keychain:" }

// Close returns nil.
func (k *KeychainBackend) Close() error { return nil }

// VerifyACL returns ErrUnavailable.
func (k *KeychainBackend) VerifyACL(_ context.Context) error { return backend.ErrUnavailable }

// RepairACL returns ErrUnavailable.
func (k *KeychainBackend) RepairACL(_ context.Context) error { return backend.ErrUnavailable }

// RepairItemACLs returns ErrUnavailable.
func (k *KeychainBackend) RepairItemACLs(_ context.Context) error { return backend.ErrUnavailable }

// Init returns ErrUnavailable.
func (k *KeychainBackend) Init(_ context.Context, _ string) error { return backend.ErrUnavailable }
