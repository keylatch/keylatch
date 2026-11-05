package brokerd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// firstAccountID is where Windows partitions start numbering; it matches the
// lowest user id the broker admits elsewhere.
const firstAccountID = DefaultMinUID

// ErrAccountsFull means every id in the admitted range is taken.
var ErrAccountsFull = errors.New("brokerd: no partition ids are left")

// AccountMap gives each Windows user SID a stable number, so a partition keeps
// its directory and its keys when the same person connects again. The number is
// only a name for the partition; the SID is what is authenticated.
type AccountMap struct {
	path string

	mu   sync.Mutex
	sids map[string]uint32
	next uint32
}

type accountsFile struct {
	Next     uint32            `json:"next"`
	Accounts map[string]uint32 `json:"accounts"`
}

// OpenAccounts loads the map stored at path, which may not exist yet.
func OpenAccounts(path string) (*AccountMap, error) {
	m := &AccountMap{path: path, sids: map[string]uint32{}, next: firstAccountID}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a path under the service's state directory
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var f accountsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("brokerd: accounts: %w", err)
	}
	if f.Accounts != nil {
		m.sids = f.Accounts
	}
	m.next = max(f.Next, firstAccountID)
	for _, id := range m.sids {
		m.next = max(m.next, id+1)
	}
	return m, nil
}

// Find returns the number of sid, if it has one.
func (m *AccountMap) Find(sid string) (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sids[sid]
	return id, ok
}

// SID returns the account a partition number belongs to.
func (m *AccountMap) SID(id uint32) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sid, n := range m.sids {
		if n == id {
			return sid, true
		}
	}
	return "", false
}

// UID returns the number of sid and assigns the next free one on first sight.
func (m *AccountMap) UID(sid string) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.sids[sid]; ok {
		return id, nil
	}
	if m.next > DefaultMaxUID {
		return 0, ErrAccountsFull
	}
	id := m.next
	m.sids[sid] = id
	m.next++
	if err := m.save(); err != nil {
		delete(m.sids, sid)
		m.next--
		return 0, err
	}
	return id, nil
}

func (m *AccountMap) save() error {
	b, err := json.Marshal(accountsFile{Next: m.next, Accounts: m.sids})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	tmp := m.path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
