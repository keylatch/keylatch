// Package memory provides an in-process key-value backend for testing.
// It is NOT safe for production use — data is lost when the process exits.
package memory

import (
	"context"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// Backend is a thread-safe in-memory backend implementing backend.Backend.
// All metadata and versioned methods return backend.ErrNotSupported so that
// the compliance harness skips them gracefully.
type Backend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// New returns an empty in-memory backend.
func New() *Backend {
	return &Backend{data: make(map[string][]byte)}
}

// Name implements backend.Backend.
func (b *Backend) Name() string { return "memory" }

// ID implements backend.Backend.
func (b *Backend) ID() string { return "memory:in-process" }

// Capabilities implements backend.Backend.
func (b *Backend) Capabilities() []backend.Capability {
	return []backend.Capability{backend.CapList}
}

// Get returns the stored bytes for path or ErrNotFound.
func (b *Backend) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, backend.Meta{Path: path, Backend: "memory"}, nil
}

// Set stores a copy of value at path.
func (b *Backend) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	b.data[path] = cp
	return nil
}

// Delete removes path. Idempotent — deleting a missing key is not an error.
func (b *Backend) Delete(_ context.Context, path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, path)
	return nil
}

// List returns metadata-only entries whose paths share the given prefix.
func (b *Backend) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var entries []backend.Entry
	for k := range b.data {
		if strings.HasPrefix(k, prefix) {
			entries = append(entries, backend.Entry{
				Meta:   backend.Meta{Path: k, Backend: "memory"},
				Exists: true,
			})
		}
	}
	return entries, nil
}

// GetMeta is not supported by the memory backend.
func (b *Backend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by the memory backend.
func (b *Backend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by the memory backend.
func (b *Backend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by the memory backend.
func (b *Backend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by the memory backend.
func (b *Backend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by the memory backend.
func (b *Backend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the memory backend.
func (b *Backend) Close() error { return nil }
