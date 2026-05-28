package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// atomicWrite writes data to path atomically: write to a temp file, fsync the
// temp file, rename to path, fsync the parent directory.
//
// S5-19: post-failure the file at path is one of two consistent states — the
// previous contents or the new contents. Never partial.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)

	// Step 1: write to temp file in same directory.
	tmp, err := os.CreateTemp(dir, ".keyring-*.tmp")
	if err != nil {
		return fmt.Errorf("atomicWrite: create temp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	// Step 2: set mode before writing data.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicWrite: chmod: %w", err)
	}

	// Step 3: write data.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicWrite: write: %w", err)
	}

	// Step 4: fsync the temp file.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicWrite: fsync temp: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicWrite: close temp: %w", err)
	}

	// Step 5: rename temp → target.
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomicWrite: rename: %w", err)
	}
	cleanup = false

	// Step 6: fsync the parent directory to make the rename durable.
	parentDir, err := os.Open(dir)
	if err != nil {
		// Non-fatal: rename already succeeded.
		return nil
	}
	_ = parentDir.Sync()
	_ = parentDir.Close()

	return nil
}

// loadFile reads and JSON-decodes a KeyringFile from path.
// Returns ErrKeyringNotFound if the file is absent, ErrKeyringCorrupt on any
// other read or parse failure.
//
// Validates:
//   - File mode is exactly 0o600.
//   - SchemaVersion == SchemaVersion (1).
func loadFile(path string) (KeyringFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return KeyringFile{}, ErrKeyringNotFound
		}
		return KeyringFile{}, fmt.Errorf("%w: stat %q: %v", ErrKeyringCorrupt, path, err)
	}

	if enforcePrivateFileMode && info.Mode().Perm() != 0o600 {
		return KeyringFile{}, fmt.Errorf("%w: %q has mode %04o, want 0600", ErrKeyringCorrupt, path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return KeyringFile{}, fmt.Errorf("%w: read %q: %v", ErrKeyringCorrupt, path, err)
	}

	var kf KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return KeyringFile{}, fmt.Errorf("%w: parse %q: %v", ErrKeyringCorrupt, path, err)
	}

	// Accept schema versions 1 (Phase 5 legacy) and 2 (Phase 11+).
	// Version 1 keyrings are migrated on Open; version > SchemaVersion is rejected.
	if kf.SchemaVersion < 1 || kf.SchemaVersion > SchemaVersion {
		return KeyringFile{}, fmt.Errorf("%w: %q has schema version %d, want 1 or %d",
			ErrKeyringCorrupt, path, kf.SchemaVersion, SchemaVersion)
	}

	return kf, nil
}

// ReadHeader reads and returns the KeyringFile metadata from path without
// requiring a KEK. Useful for determining the KEK type before loading.
// Returns ErrKeyringNotFound if the file does not exist.
func ReadHeader(path string) (KeyringFile, error) {
	return loadFile(path)
}

// saveFile serializes kf to JSON and writes it atomically to path.
func saveFile(path string, kf KeyringFile) error {
	data, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("keyring: marshal: %w", err)
	}
	return atomicWrite(path, data)
}
