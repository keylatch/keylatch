package brokerd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

// syncState is the daemon's record of what it wrote to each target: a keyed
// hash of the value and the update time the target reported. The key comes
// from the daemon's key hierarchy, so a value is compared with what was
// written without any plain hash of it existing, and without the CLI or an
// agent being able to recompute one.
type syncState struct {
	path string
	key  func() ([]byte, error)

	mu     sync.Mutex
	loaded bool
	m      map[string]syncRecord
}

type syncRecord struct {
	MAC      string    `json:"mac"`
	RemoteAt time.Time `json:"remote_at"`
}

func newSyncState(dir string, key func() ([]byte, error)) *syncState {
	return &syncState{path: filepath.Join(dir, "sync-state.json"), key: key}
}

func (s *syncState) load() error {
	if s.loaded {
		return nil
	}
	s.m = map[string]syncRecord{}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &s.m); err != nil {
			return fmt.Errorf("sync state: %w", err)
		}
	}
	s.loaded = true
	return nil
}

func (s *syncState) save() error {
	b, err := json.Marshal(s.m)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func recordKey(id, env, name string) string { return id + "\x00" + env + "\x00" + name }

// Written implements keysync.State.
func (s *syncState) Written(id, env, name string) (keysync.Written, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.load() != nil {
		return keysync.Written{}, false
	}
	r, ok := s.m[recordKey(id, env, name)]
	return keysync.Written{MAC: r.MAC, RemoteAt: r.RemoteAt}, ok
}

// MAC is HMAC-SHA256 under the partition's sync key over the target identity,
// environment, name and value, each length-prefixed.
func (s *syncState) MAC(id, env, name string, value []byte) string {
	k, err := s.key()
	if err != nil {
		return "unavailable"
	}
	defer clear(k)
	h := hmac.New(sha256.New, k)
	for _, p := range []string{id, env, name} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}

// Record implements keysync.Recorder.
func (s *syncState) Record(id, env, name, mac string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	s.m[recordKey(id, env, name)] = syncRecord{MAC: mac, RemoteAt: at.UTC()}
	return s.save()
}

// Forget implements keysync.Recorder.
func (s *syncState) Forget(id, env, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	delete(s.m, recordKey(id, env, name))
	return s.save()
}
