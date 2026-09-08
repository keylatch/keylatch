// Package file implements the envelope-encrypted file backend.
// layout.go defines path construction helpers for the on-disk layout:
//
//	<root>/metadata/<canonical>.json   — value-free metadata
//	<root>/values/<canonical>/<N>      — encrypted value records
//	<root>/receipts/<canonical>/       — runtime delivery receipts
//
// All paths use filepath.FromSlash for cross-platform safety.
package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// confine joins base with the given elements and verifies the result stays
// under base — rejecting a canonical path containing ".." (or an absolute
// path) instead of silently escaping the values/metadata directory (F37).
// Callers must not use filepath.Join directly on a caller-influenced
// canonical path for this reason.
func confine(base string, elem ...string) (string, error) {
	full := filepath.Join(append([]string{base}, elem...)...)
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("file backend: path escapes vault root: %q", filepath.Join(elem...))
	}
	return full, nil
}

// metadataPath returns the full path to the metadata JSON file for a
// canonical secret path.
//
// Example: root="~/.keylatch/vault", canonical="default/ai/openrouter/api_key"
//
//	→ "~/.keylatch/vault/metadata/default/ai/openrouter/api_key.json"
func metadataPath(root, canonical string) (string, error) {
	p, err := confine(filepath.Join(root, "metadata"), filepath.FromSlash(canonical))
	if err != nil {
		return "", err
	}
	return p + ".json", nil
}

// valuePath returns the full path to an encrypted value record for a given
// canonical path and version number.
//
// Example: root="~/.keylatch/vault", canonical="default/ai/openrouter/api_key", version=2
//
//	→ "~/.keylatch/vault/values/default/ai/openrouter/api_key/2"
func valuePath(root, canonical string, version int) (string, error) {
	return confine(filepath.Join(root, "values"), filepath.FromSlash(canonical), strconv.Itoa(version))
}

// ensureDir creates all parent directories of the given file path with mode
// 0700. Returns nil if the directories already exist.
func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}
