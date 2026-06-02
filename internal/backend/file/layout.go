// Package file implements the envelope-encrypted file backend.
// layout.go defines path construction helpers for the Phase 4 on-disk layout:
//
//	<root>/metadata/<canonical>.json   — Phase 4 value-free metadata
//	<root>/values/<canonical>/<N>      — encrypted value records
//	<root>/receipts/<canonical>/       — runtime delivery receipts
//
// All paths use filepath.FromSlash for cross-platform safety.
package file

import (
	"os"
	"path/filepath"
	"strconv"
)

// metadataPath returns the full path to the Phase 4 metadata JSON file for a
// canonical secret path.
//
// Example: root="~/.keylatch/vault", canonical="default/ai/openrouter/api_key"
//
//	→ "~/.keylatch/vault/metadata/default/ai/openrouter/api_key.json"
func metadataPath(root, canonical string) string {
	return filepath.Join(root, "metadata", filepath.FromSlash(canonical)) + ".json"
}

// valuePath returns the full path to an encrypted value record for a given
// canonical path and version number.
//
// Example: root="~/.keylatch/vault", canonical="default/ai/openrouter/api_key", version=2
//
//	→ "~/.keylatch/vault/values/default/ai/openrouter/api_key/2"
func valuePath(root, canonical string, version int) string {
	return filepath.Join(root, "values", filepath.FromSlash(canonical), strconv.Itoa(version))
}

// ensureDir creates all parent directories of the given file path with mode
// 0700. Returns nil if the directories already exist.
func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}
