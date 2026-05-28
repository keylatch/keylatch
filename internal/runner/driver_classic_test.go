package runner_test

// driver_classic_test.go — shared test helpers for the runner package.
//
// The direct_classic and direct_classic_sandboxed drivers were removed in
// v1.0.0 (T-10-03). The test stubs that exercised those drivers have been
// deleted. This file retains only the shared infrastructure helpers used by
// other test files in this package (classicMockBackend, classicSecretPath).

import (
	"context"
	"fmt"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// classicMockBackend is an in-memory backend used by runner tests.
type classicMockBackend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newClassicMockBackend() *classicMockBackend {
	return &classicMockBackend{data: map[string][]byte{}}
}

func (m *classicMockBackend) Name() string                       { return "classic-mock" }
func (m *classicMockBackend) Capabilities() []backend.Capability { return nil }
func (m *classicMockBackend) ID() string                         { return "classic-mock" }
func (m *classicMockBackend) Close() error                       { return nil }

func (m *classicMockBackend) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, backend.Meta{Path: path, Backend: "classic-mock", Version: 1}, nil
}

func (m *classicMockBackend) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[path] = cp
	return nil
}

func (m *classicMockBackend) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[path]; !ok {
		return backend.ErrNotFound
	}
	delete(m.data, path)
	return nil
}

func (m *classicMockBackend) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, nil
}

func (m *classicMockBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

func (m *classicMockBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

func (m *classicMockBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

func (m *classicMockBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

func (m *classicMockBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

func (m *classicMockBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// classicSecretPath mirrors the lookup path used by brokeredDriver and
// dispatch tests. Returns the canonical four-segment path format.
//
// S-FIND-23 (T-03-01): uses canonical "namespace/category/provider/field"
// format (e.g. "default/ai/myapi/api_key"). The account segment from the
// legacy format is dropped — v1.0.0 has no existing users with legacy entries.
// The "category" parameter should be the provider's category (e.g. "ai").
// When empty, "ai" is used as the default.
func classicSecretPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/%s", namespace, category, provider, field)
}
