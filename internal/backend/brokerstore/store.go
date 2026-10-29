// Package brokerstore is the secret store inside the broker daemon. Every
// secret is sealed under its own random data key (DEK), and the DEK is wrapped
// by the partition's key-encryption key. The additional authenticated data of
// both layers is partition ‖ path ‖ version, checked on every read, so a record
// copied to another path, version or partition does not open.
package brokerstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/keylatch/keylatch/internal/backend"
)

// Name is the backend name recorded in metadata.
const Name = "broker"

const (
	recordFormat = 1
	dekLen       = 32
	maxPathLen   = 512
)

// ErrAAD means a record does not belong at the path, version and partition it
// was read for, or was altered.
var ErrAAD = errors.New("brokerstore: record failed its integrity check")

// KEKSource hands out the partition's key-encryption keys.
type KEKSource interface {
	// StoreKEK returns the current key and the id of the master key it comes from.
	StoreKEK(partition string) (kid string, key []byte)
	// KEKFor returns the key under the master key named kid.
	KEKFor(kid, partition string) ([]byte, error)
}

type record struct {
	V          int       `json:"v"`
	Path       string    `json:"path"`
	Version    int       `json:"version"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	KID        string    `json:"kid"`
	DEKNonce   []byte    `json:"dek_nonce"`
	WrappedDEK []byte    `json:"wrapped_dek"`
	Nonce      []byte    `json:"nonce"`
	CT         []byte    `json:"ct"`
}

// Store is one partition's secret store.
type Store struct {
	dir       string
	partition string
	keys      KEKSource
	now       func() time.Time

	mu sync.Mutex
}

// Open opens the store of a partition under dir, creating the directory.
func Open(dir, partition string, keys KEKSource) (*Store, error) {
	if partition == "" || strings.ContainsRune(partition, 0) {
		return nil, errors.New("brokerstore: a partition name is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("brokerstore: %w", err)
	}
	return &Store{dir: dir, partition: partition, keys: keys, now: time.Now}, nil
}

// Put stores value at p as the next version.
func (s *Store) Put(_ context.Context, p string, value []byte) (int, error) {
	if err := validPath(p); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	version, created := 1, s.now().UTC()
	if old, err := s.read(p); err == nil {
		value, _, err := s.decrypt(old)
		clear(value)
		if err != nil {
			return 0, err
		}
		version, created = old.Version+1, old.Created
		if version <= old.Version {
			return 0, errors.New("brokerstore: version limit reached")
		}
		if err := s.writeTo(s.versionFile(p, old.Version), old); err != nil {
			return 0, err
		}
	} else if !errors.Is(err, backend.ErrNotFound) {
		return 0, err
	}
	dek := make([]byte, dekLen)
	defer clear(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return 0, fmt.Errorf("brokerstore: %w", err)
	}
	aad := s.aad(p, version)
	nonce, ct, err := seal(dek, value, aad)
	if err != nil {
		return 0, err
	}
	kid, kek := s.keys.StoreKEK(s.partition)
	defer clear(kek)
	dekNonce, wrapped, err := seal(kek, dek, append(aad, kid...))
	if err != nil {
		return 0, err
	}
	rec := record{V: recordFormat, Path: p, Version: version, Created: created, Updated: s.now().UTC(),
		KID: kid, DEKNonce: dekNonce, WrappedDEK: wrapped, Nonce: nonce, CT: ct}
	return version, s.write(rec)
}

// Get returns the plaintext at p. The caller wipes it.
func (s *Store) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	if err := validPath(p); err != nil {
		return nil, backend.Meta{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(p)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	return s.decrypt(rec)
}

// GetVersion returns an authenticated historical value; the caller wipes it.
// A deleted source has no readable history, even if cleanup was interrupted.
func (s *Store) GetVersion(_ context.Context, p string, version int) ([]byte, backend.Meta, error) {
	if err := validPath(p); err != nil {
		return nil, backend.Meta{}, err
	}
	if version < 1 {
		return nil, backend.Meta{}, errors.New("brokerstore: version must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read(p)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	if version == current.Version {
		return s.decrypt(current)
	}
	value, _, err := s.decrypt(current)
	clear(value)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	if version > current.Version {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return s.history(p, version)
}

// Snapshot reads current and previous values under one lock; the caller wipes both.
// Missing history is returned as nil, while corrupt history fails the whole read.
func (s *Store) Snapshot(_ context.Context, p string) (current, previous []byte, m backend.Meta, err error) {
	if err = validPath(p); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.read(p)
	if err != nil {
		return nil, nil, backend.Meta{}, err
	}
	current, m, err = s.decrypt(rec)
	if err != nil || rec.Version == 1 {
		return
	}
	previous, _, err = s.history(p, rec.Version-1)
	if errors.Is(err, backend.ErrNotFound) {
		err = nil
	} else if err != nil {
		clear(current)
		return nil, nil, backend.Meta{}, err
	}
	return
}

func (s *Store) history(p string, version int) ([]byte, backend.Meta, error) {
	var rec record
	if err := readJSON(s.versionFile(p, version), &rec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, backend.Meta{}, backend.ErrNotFound
		}
		return nil, backend.Meta{}, err
	}
	if rec.V != recordFormat || rec.Path != p || rec.Version != version {
		return nil, backend.Meta{}, ErrAAD
	}
	return s.decrypt(rec)
}

// decrypt checks both encryption layers; the caller holds mu.
func (s *Store) decrypt(rec record) ([]byte, backend.Meta, error) {
	p := rec.Path
	aad := s.aad(p, rec.Version)
	kek, err := s.keys.KEKFor(rec.KID, s.partition)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("brokerstore: %w", err)
	}
	defer clear(kek)
	dek, err := open(kek, rec.DEKNonce, rec.WrappedDEK, append(aad, rec.KID...))
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: data key", ErrAAD)
	}
	defer clear(dek)
	value, err := open(dek, rec.Nonce, rec.CT, aad)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: value", ErrAAD)
	}
	return value, meta(rec), nil
}

// Delete removes p.
func (s *Store) Delete(_ context.Context, p string) error {
	if err := validPath(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	missing := false
	if err := os.Remove(s.file(p)); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("brokerstore: %w", err)
		}
		missing = true
	}
	files, err := filepath.Glob(strings.TrimSuffix(s.file(p), ".json") + ".v*.json")
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("brokerstore: remove history: %w", err)
		}
	}
	if missing {
		return backend.ErrNotFound
	}
	return nil
}

// List returns the metadata of every secret under prefix. It decrypts nothing.
func (s *Store) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("brokerstore: %w", err)
	}
	var out []backend.Entry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || strings.Contains(f.Name(), ".v") {
			continue
		}
		var rec record
		if readJSON(filepath.Join(s.dir, f.Name()), &rec) != nil || !strings.HasPrefix(rec.Path, prefix) {
			continue
		}
		out = append(out, backend.Entry{Meta: meta(rec), Exists: true})
	}
	return out, nil
}

// Rewrap moves every record's data key from oldKEK to newKEK, tagging it
// newKID. Values are not touched. Records already at newKID are skipped, so an
// interrupted rewrap can run again.
func (s *Store) Rewrap(oldKEK, newKEK []byte, newKID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("brokerstore: %w", err)
	}
	n := 0
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		var rec record
		if err := readJSON(filepath.Join(s.dir, f.Name()), &rec); err != nil {
			return n, err
		}
		if rec.V != recordFormat || rec.Version < 1 || (f.Name() != filepath.Base(s.file(rec.Path)) && f.Name() != filepath.Base(s.versionFile(rec.Path, rec.Version))) {
			return n, ErrAAD
		}
		if rec.KID == newKID {
			continue
		}
		aad := s.aad(rec.Path, rec.Version)
		dek, err := open(oldKEK, rec.DEKNonce, rec.WrappedDEK, append(aad, rec.KID...))
		if err != nil {
			return n, fmt.Errorf("%w: data key of %s", ErrAAD, rec.Path)
		}
		nonce, wrapped, err := seal(newKEK, dek, append(aad, newKID...))
		clear(dek)
		if err != nil {
			return n, err
		}
		rec.KID, rec.DEKNonce, rec.WrappedDEK = newKID, nonce, wrapped
		if err := s.writeTo(filepath.Join(s.dir, f.Name()), rec); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func meta(rec record) backend.Meta {
	return backend.Meta{Path: rec.Path, Version: rec.Version, CreatedAt: rec.Created, UpdatedAt: rec.Updated, Backend: Name}
}

func (s *Store) file(p string) string {
	sum := sha256.Sum256([]byte(p))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

func (s *Store) versionFile(p string, version int) string {
	return strings.TrimSuffix(s.file(p), ".json") + fmt.Sprintf(".v%d.json", version)
}

func (s *Store) read(p string) (record, error) {
	var rec record
	if err := readJSON(s.file(p), &rec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rec, backend.ErrNotFound
		}
		return rec, err
	}
	if rec.V != recordFormat || rec.Path != p || rec.Version < 1 {
		return rec, fmt.Errorf("%w: record names another path", ErrAAD)
	}
	return rec, nil
}

func (s *Store) write(rec record) error {
	return s.writeTo(s.file(rec.Path), rec)
}

func (s *Store) writeTo(dst string, rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".record-")
	if err != nil {
		return fmt.Errorf("brokerstore: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("brokerstore: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("brokerstore: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("brokerstore: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("brokerstore: %w", err)
	}
	return nil
}

// aad is partition ‖ path ‖ version, each field length-delimited.
func (s *Store) aad(p string, version int) []byte {
	out := []byte("keylatch/store/v1\x00" + s.partition + "\x00" + p + "\x00")
	return binary.BigEndian.AppendUint64(out, uint64(version)) //nolint:gosec // G115: version is positive
}

func validPath(p string) error {
	switch {
	case p == "" || len(p) > maxPathLen:
		return errors.New("brokerstore: a secret path of 1 to 512 bytes is required")
	case strings.ContainsRune(p, 0) || path.Clean(p) != p || strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("brokerstore: %q is not a canonical relative path", p)
	}
	return nil
}

func seal(key, plain, aad []byte) (nonce, ct []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("brokerstore: %w", err)
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("brokerstore: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plain, aad), nil
}

func open(key, nonce, ct, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("malformed nonce")
	}
	return aead.Open(nil, nonce, ct, aad)
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p) //nolint:gosec // G304: inside the partition's store directory
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("brokerstore: %s: %w", filepath.Base(p), err)
	}
	return nil
}
