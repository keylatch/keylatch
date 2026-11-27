package file

import (
	"fmt"
	"os"
	"path/filepath"
)

// lockVault takes an exclusive lock, shared by every process that opens this
// vault, and returns the function that releases it. Writers hold it from the
// moment they reload the manifest until they have saved it, so two processes
// writing at once cannot each save a manifest that lacks the other's entry.
func (fb *FileBackend) lockVault() (release func(), err error) {
	f, err := os.OpenFile(filepath.Join(fb.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("file backend: open lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("file backend: lock vault: %w", err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// reloadManifestLocked discards the cached manifest and reads it again. Callers
// hold fb.mu and the vault lock.
func (fb *FileBackend) reloadManifestLocked() error {
	fb.loaded = false
	return fb.ensureManifestLocked()
}
