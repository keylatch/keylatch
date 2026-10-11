// Package salt provides load-or-create for the 32-byte audit HMAC salt file.
package salt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreate returns the 32-byte HMAC salt from path, creating it atomically
// if absent.
//
// Security invariants:
// - File mode is enforced as exactly 0o600 on read.
// - The salt bytes are NEVER logged or printed.
func LoadOrCreate(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err == nil {
		// File exists — validate mode.
		if enforcePrivateFileMode && info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("%w: %q has mode %04o, want 0600",
				ErrSaltUnavailable, path, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read %q: %v", ErrSaltUnavailable, path, err)
		}
		if len(data) != 32 {
			return nil, fmt.Errorf("%w: %q has %d bytes, want 32",
				ErrSaltUnavailable, path, len(data))
		}
		return data, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: stat %q: %v", ErrSaltUnavailable, path, err)
	}

	// File absent — generate and write atomically.
	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, fmt.Errorf("%w: generate salt: %v", ErrSaltUnavailable, err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".audit-salt-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("%w: create temp: %v", ErrSaltUnavailable, err)
	}
	tmpName := tmp.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp opens the file with mode 0600.
	_, err = tmp.Write(saltBytes)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("%w: write temp: %v", ErrSaltUnavailable, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("%w: rename: %v", ErrSaltUnavailable, err)
	}
	cleanup = false

	return saltBytes, nil
}

// ErrSaltUnavailable is returned when the salt file cannot be read or created.
var ErrSaltUnavailable = errors.New("audit: salt unavailable")
