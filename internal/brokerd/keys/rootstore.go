package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RootStore keeps the device root where only the daemon's account can read it:
// the System keychain on macOS, a CNG-sealed file on Windows.
type RootStore interface {
	// Name says where the root lives, for status output.
	Name() string
	// Load returns the root, or ErrNoRoot when none was created.
	Load() ([]byte, error)
	// Create stores a new random root unless one exists and reports whether it
	// created one. It never replaces a root: that would orphan every key
	// wrapped under it.
	Create(rd io.Reader) (bool, error)
}

// Sealer protects bytes with a key that stays in the platform's key store.
type Sealer interface {
	Name() string
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// SealedFile stores the root as a file the Sealer protects. With a nil Sealer
// the file holds the root itself and its mode and owner are the only barrier;
// that is the fallback where no platform key store is available.
type SealedFile struct {
	Path   string
	Sealer Sealer
	// Own gives the new file to the daemon's account; it runs as the installer.
	Own func(path string) error
}

// Name implements RootStore.
func (s SealedFile) Name() string {
	if s.Sealer == nil {
		return "root file"
	}
	return s.Sealer.Name()
}

// Load implements RootStore.
func (s SealedFile) Load() ([]byte, error) {
	b, err := os.ReadFile(s.Path) //nolint:gosec // G304: the installer fixes the path
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %v", ErrNoRoot, err)
	}
	if err != nil {
		return nil, err
	}
	if s.Sealer == nil {
		if len(b) < rootMinLen {
			clear(b)
			return nil, ErrNoRoot
		}
		return b, nil
	}
	plain, err := s.Sealer.Open(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRoot, err)
	}
	if len(plain) < rootMinLen {
		clear(plain)
		return nil, ErrNoRoot
	}
	return plain, nil
}

// Create implements RootStore.
func (s SealedFile) Create(rd io.Reader) (bool, error) {
	if _, err := os.Stat(s.Path); err == nil {
		return false, nil
	}
	if rd == nil {
		rd = rand.Reader
	}
	secret := make([]byte, keyLen)
	defer clear(secret)
	if _, err := io.ReadFull(rd, secret); err != nil {
		return false, fmt.Errorf("keys: generate the device root: %w", err)
	}
	body := secret
	if s.Sealer != nil {
		sealed, err := s.Sealer.Seal(secret)
		if err != nil {
			return false, fmt.Errorf("keys: seal the device root: %w", err)
		}
		body = sealed
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil { //nolint:gosec // G301: the directory holds only the sealed root
		return false, err
	}
	f, err := os.OpenFile(s.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // G304: the installer fixes the path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(s.Path)
		return false, err
	}
	if s.Own != nil {
		if err := s.Own(s.Path); err != nil {
			_ = os.Remove(s.Path)
			return false, fmt.Errorf("keys: hand the device root to the daemon account: %w", err)
		}
	}
	return true, nil
}
