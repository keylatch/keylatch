package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const installIDFile = "install_id"

// EnsureInstallID reads the install ID from dataDir/install_id, creating it
// (mode 0o600) with a randomly generated v4-style UUID if absent.
// The file contains a 32-character lowercase hex string (16 random bytes).
// All errors are returned to the caller; callers should fall back to a
// session-scoped ID if EnsureInstallID fails.
func EnsureInstallID(dataDir string) (string, error) {
	path := filepath.Join(dataDir, installIDFile)

	// Fast path: read existing ID.
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) == 32 {
			return id, nil
		}
		// File exists but content is malformed — regenerate.
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read install_id: %w", err)
	}

	// Generate a new v4-style install ID: 16 random bytes hex-encoded (32 chars).
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate install_id: %w", err)
	}
	// Set version (4) and variant bits to produce a UUID v4-compatible layout.
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits

	id := hex.EncodeToString(b[:])

	// Ensure the data directory exists.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir dataDir for install_id: %w", err)
	}

	// Write atomically: temp file → rename.
	tmp, err := os.CreateTemp(dataDir, ".install_id-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp install_id: %w", err)
	}
	tmpName := tmp.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod install_id: %w", err)
	}
	if _, err := fmt.Fprintln(tmp, id); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write install_id: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp install_id: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("rename install_id: %w", err)
	}

	success = true
	return id, nil
}
