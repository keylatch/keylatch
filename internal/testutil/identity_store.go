package testutil

import (
	"errors"
	"sync"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// MemoryIdentityStore is an in-memory kek.IdentityStore standing in for the
// OS keyring. Set StoreErr to simulate an unusable keyring.
type MemoryIdentityStore struct {
	mu       sync.Mutex
	items    map[string][]byte
	StoreErr error
}

var _ kek.IdentityStore = (*MemoryIdentityStore)(nil)

// NewMemoryIdentityStore returns an empty store.
func NewMemoryIdentityStore() *MemoryIdentityStore {
	return &MemoryIdentityStore{items: map[string][]byte{}}
}

func (m *MemoryIdentityStore) Name() string { return "memory" }

func (m *MemoryIdentityStore) Load(account string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[account]
	if !ok {
		return nil, kek.ErrIdentityNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *MemoryIdentityStore) Store(account string, identity []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.StoreErr != nil {
		return m.StoreErr
	}
	m.items[account] = append([]byte(nil), identity...)
	return nil
}

func (m *MemoryIdentityStore) Delete(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[account]; !ok {
		return kek.ErrIdentityNotFound
	}
	delete(m.items, account)
	return nil
}

// Len reports how many items the store holds.
func (m *MemoryIdentityStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// ErrKeyringLocked is a convenience StoreErr value.
var ErrKeyringLocked = errors.New("keyring locked")
