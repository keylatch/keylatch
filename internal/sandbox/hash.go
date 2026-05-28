// Package sandbox — hash.go provides streaming SHA-256 hashing for executables.
//
// HashExecutable streams the file in chunks rather than loading it all into
// memory, making it safe for large binaries. The result is a lowercase hex
// string matching the format expected by SandboxManifest.ExecHash.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashExecutable computes the SHA-256 hex digest of the file at path by
// streaming its contents. Returns an error if the file cannot be opened or read.
//
// The returned string is lowercase hex (64 characters), matching the format
// of SandboxManifest.ExecHash.
func HashExecutable(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: caller validates path provenance
	if err != nil {
		return "", fmt.Errorf("sandbox: open executable for hashing %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("sandbox: hash executable %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
