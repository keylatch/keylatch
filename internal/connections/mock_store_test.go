package connections

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
)

// mockStore is an in-memory Store implementation for tests.
type mockStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{data: map[string][]byte{}}
}

func (m *mockStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return v, backend.Meta{Path: path, Backend: "mock", Version: 1, UpdatedAt: time.Now()}, nil
}

func (m *mockStore) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Store a copy to prevent caller from zeroing it.
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[path] = cp
	return nil
}

func (m *mockStore) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entries []backend.Entry
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			entries = append(entries, backend.Entry{
				Meta:   backend.Meta{Path: k, Backend: "mock"},
				Exists: true,
			})
		}
	}
	return entries, nil
}

func (m *mockStore) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[path]; !ok {
		return backend.ErrNotFound
	}
	delete(m.data, path)
	return nil
}

// storedValue returns a copy of the stored value for a path (for test assertions).
func (m *mockStore) storedValue(path string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, true
}

// errStore always returns an error on Set/Get.
type errStore struct{ err error }

func (e errStore) Get(_ context.Context, _ string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, errors.New("store unavailable")
}
func (e errStore) Set(_ context.Context, _ string, _ []byte, _ backend.Meta) error {
	return errors.New("store unavailable")
}
func (e errStore) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, errors.New("store unavailable")
}
func (e errStore) Delete(_ context.Context, _ string) error {
	return errors.New("store unavailable")
}
