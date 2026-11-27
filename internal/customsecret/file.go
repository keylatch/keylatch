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
	return os.Rename(tmp.Name(), path)
}

// Add appends s, refusing a duplicate name.
func Add(path string, s Secret) error {
	secrets, err := Load(path)
	if err != nil {
		return err
	}
	for _, e := range secrets {
		if e.Name == s.Name {
			return fmt.Errorf("%w: %s", ErrExists, s.Name)
		}
	}
	return Save(path, append(secrets, s))
}

// Remove deletes the named entry.
func Remove(path, name string) error {
	secrets, err := Load(path)
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
	return Save(path, kept)
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

// Replace overwrites the entry with the same name, keeping its creation time.
func Replace(path string, s Secret) error {
	secrets, err := Load(path)
	if err != nil {
		return err
	}
	for i, e := range secrets {
		if e.Name == s.Name {
			s.CreatedAt = e.CreatedAt
			secrets[i] = s
			return Save(path, secrets)
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, s.Name)
}
