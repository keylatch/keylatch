package file

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// getMetaFromDisk reads and returns the Phase 4 metadata for a canonical path.
// Returns backend.ErrNotFound if the metadata file does not exist.
func getMetaFromDisk(root, path string) (vmeta.Meta, error) {
	p := metadataPath(root, path)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return vmeta.Meta{}, backend.ErrNotFound
		}
		return vmeta.Meta{}, err
	}

	var m vmeta.Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return vmeta.Meta{}, err
	}
	return m, nil
}

// SetMeta writes Phase 4 metadata for path atomically:
// temp file + fsync + rename. Uses mode 0o600 (S4-2).
func (fb *FileBackend) SetMeta(_ context.Context, path string, m vmeta.Meta) error {
	p := metadataPath(fb.dir, path)

	if err := ensureDir(p); err != nil {
		return err
	}

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}

	return atomicWrite(p, data, 0o600)
}

// ListMeta returns all stored Phase 4 metadata records whose Path starts with
// the given prefix. An empty prefix returns all records. Results are sorted by
// Meta.Path. MUST NOT read any value files (S4-1).
func (fb *FileBackend) ListMeta(_ context.Context, prefix string) ([]vmeta.Meta, error) {
	root := filepath.Join(fb.dir, "metadata")

	var metas []vmeta.Meta
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path) //nolint:gosec // G122: path originates from WalkDir under a validated vault root; no user input
		if err != nil {
			return err
		}

		var m vmeta.Meta
		if err := json.Unmarshal(data, &m); err != nil {
			// Skip malformed files rather than aborting the walk.
			return nil
		}

		if prefix == "" || strings.HasPrefix(m.Path, prefix) {
			metas = append(metas, m)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Path < metas[j].Path
	})
	return metas, nil
}
