package customsecret

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ErrNotFound is returned when no custom secret has the requested name.
var ErrNotFound = errors.New("custom secret not found")

// ErrExists is returned when a custom secret with the name already exists.
var ErrExists = errors.New("custom secret already exists")

type fileDoc struct {
	Secrets []Secret `json:"secrets"`
}

// Load reads the metadata file; a missing file is an empty list.
func Load(path string) ([]Secret, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc fileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc.Secrets, nil
}

// Save writes the metadata file atomically with owner-only permissions.
func Save(path string, secrets []Secret) error {
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Name < secrets[j].Name })
	if secrets == nil {
		secrets = []Secret{}
	}
	data, err := json.MarshalIndent(fileDoc{Secrets: secrets}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".custom-secrets-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmp.Name(), path)
}

// Tx is a locked view of the rules file. Every read-modify-write that spans
// more than one step (check, write the value, save the rules) runs in one Tx.
type Tx struct{ path string }

// WithLock runs fn while holding the advisory lock on the rules file.
func WithLock(path string, fn func(tx Tx) error) error {
	unlock, err := lockFile(path)
	if err != nil {
		return fmt.Errorf("lock %s: %w", path, err)
	}
	defer unlock()
	return fn(Tx{path: path})
}

// Find returns the named entry, ErrNotFound when it is absent, or the read error.
func (t Tx) Find(name string) (Secret, error) { return Find(t.path, name) }

// Add appends s, refusing a duplicate name.
func (t Tx) Add(s Secret) error {
	secrets, err := Load(t.path)
	if err != nil {
		return err
	}
	for _, e := range secrets {
		if e.Name == s.Name {
			return fmt.Errorf("%w: %s", ErrExists, s.Name)
		}
	}
	return Save(t.path, append(secrets, s))
}

// Replace overwrites the entry with the same name, keeping its creation time.
func (t Tx) Replace(s Secret) error {
	secrets, err := Load(t.path)
	if err != nil {
		return err
	}
	for i, e := range secrets {
		if e.Name == s.Name {
			s.CreatedAt = e.CreatedAt
			secrets[i] = s
			return Save(t.path, secrets)
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, s.Name)
}

// Remove deletes the named entry.
func (t Tx) Remove(name string) error {
	secrets, err := Load(t.path)
	if err != nil {
		return err
	}
	kept := secrets[:0]
	found := false
	for _, e := range secrets {
		if e.Name == name {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return Save(t.path, kept)
}

// Add appends s under the lock, refusing a duplicate name.
func Add(path string, s Secret) error {
	return WithLock(path, func(tx Tx) error { return tx.Add(s) })
}

// Replace overwrites the entry with the same name under the lock.
func Replace(path string, s Secret) error {
	return WithLock(path, func(tx Tx) error { return tx.Replace(s) })
}

// Remove deletes the named entry under the lock.
func Remove(path, name string) error {
	return WithLock(path, func(tx Tx) error { return tx.Remove(name) })
}

// Find returns the named entry.
func Find(path, name string) (Secret, error) {
	secrets, err := Load(path)
	if err != nil {
		return Secret{}, err
	}
	for _, e := range secrets {
		if e.Name == name {
			return e, nil
		}
	}
	return Secret{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}
