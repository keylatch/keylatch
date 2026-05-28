package file

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/backend"
)

// fileManifest is the in-memory map from canonical path to Meta.
// Stored as manifest.json in the backend data directory.
type fileManifest map[string]backend.Meta

// manifestPath returns the path to the manifest file.
func (fb *FileBackend) manifestPath() string {
	return filepath.Join(fb.dir, "manifest.json")
}

// loadManifest reads manifest.json from disk. If the file is absent,
// initializes an empty manifest (not an error — first run).
// Caller must hold the write lock.
func (fb *FileBackend) loadManifest() error {
	path := fb.manifestPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fb.manifest = make(fileManifest)
			return nil
		}
		return fmt.Errorf("file backend: read manifest: %w", err)
	}

	var m fileManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("file backend: parse manifest: %w", err)
	}
	fb.manifest = m
	return nil
}

// saveManifest writes the manifest to disk atomically (temp + fsync + rename).
// The manifest file is written with mode 0o600.
// Caller must hold the write lock.
func (fb *FileBackend) saveManifest() error {
	data, err := json.MarshalIndent(fb.manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("file backend: marshal manifest: %w", err)
	}

	return atomicWrite(fb.manifestPath(), data, 0o600)
}
