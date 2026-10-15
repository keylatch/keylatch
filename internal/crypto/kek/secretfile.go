package kek

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SecretSize is the length of the secrets kept by LoadOrCreateSecret.
const SecretSize = 32

// ErrSecretMissing is returned when the secret file does not exist and the
// caller did not ask for it to be created.
var ErrSecretMissing = errors.New("kek: wrapped secret file does not exist")

// WriteSecret stores secret wrapped by k at path, replacing any previous file
// atomically. The file is readable by its owner only.
func WriteSecret(path string, k KEK, secret []byte) error {
	wrapped, err := k.Wrap(secret)
	if err != nil {
		return fmt.Errorf("kek: wrap secret: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("kek: create secret directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, wrapped, 0o600); err != nil {
		return fmt.Errorf("kek: write secret: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("kek: install secret: %w", err)
	}
	return nil
}

// LoadOrCreateSecret returns the 32-byte secret stored wrapped by k at path.
// When the file is absent and create is true a random secret is generated and
// stored; otherwise ErrSecretMissing is returned.
func LoadOrCreateSecret(path string, k KEK, create bool) ([]byte, error) {
	wrapped, err := os.ReadFile(path) //nolint:gosec // G304: path is a keylatch-owned secret file
	switch {
	case err == nil:
		secret, uerr := k.Unwrap(wrapped)
		if uerr != nil {
			return nil, fmt.Errorf("kek: unwrap secret: %w", uerr)
		}
		if len(secret) != SecretSize {
			clear(secret)
			return nil, fmt.Errorf("kek: wrapped secret must be %d bytes", SecretSize)
		}
		return secret, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("kek: read secret: %w", err)
	case !create:
		return nil, ErrSecretMissing
	}
	secret := make([]byte, SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("kek: generate secret: %w", err)
	}
	if err := WriteSecret(path, k, secret); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}
