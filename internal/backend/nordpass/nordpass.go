// Package nordpass is a discovery-gated stub for the NordPass backend.
// All methods return errDiscoveryGated (wrapping backend.ErrUnavailable) until an
// official CLI/API contract is confirmed. See README.md for enablement conditions.
package nordpass

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// errDiscoveryGated is returned by all NordPass backend methods until an official
// CLI/API contract is confirmed. Wraps backend.ErrUnavailable so callers can use
// errors.Is(err, backend.ErrUnavailable) without importing this package.
var errDiscoveryGated = fmt.Errorf("%w: NordPass backend is discovery-gated; no official CLI/API contract has been confirmed. Set KEYLATCH_EXPERIMENTAL=1 to enable stub", backend.ErrUnavailable)

// compile-time interface check.
var _ backend.Backend = (*NordPassBackend)(nil)

// NordPassBackend is a discovery-gated stub. All methods return errDiscoveryGated.
type NordPassBackend struct{}

func (b *NordPassBackend) Name() string                       { return "nordpass" }
func (b *NordPassBackend) Capabilities() []backend.Capability { return nil }

func (b *NordPassBackend) Get(_ context.Context, _ string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, errDiscoveryGated
}

func (b *NordPassBackend) Set(_ context.Context, _ string, _ []byte, _ backend.Meta) error {
	return errDiscoveryGated
}

func (b *NordPassBackend) Delete(_ context.Context, _ string) error { return errDiscoveryGated }

func (b *NordPassBackend) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, errDiscoveryGated
}

func (b *NordPassBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

func (b *NordPassBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

func (b *NordPassBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

func (b *NordPassBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

func (b *NordPassBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

func (b *NordPassBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

func (b *NordPassBackend) ID() string   { return "nordpass:stub" }
func (b *NordPassBackend) Close() error { return nil }
