package sandbox_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashExecutable_HappyPath verifies that HashExecutable returns the correct
// SHA-256 hex digest for a known file.
func TestHashExecutable_HappyPath(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/sh\necho hello\n")
	path := filepath.Join(dir, "exec")
	require.NoError(t, os.WriteFile(path, content, 0o755))

	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])

	got, err := sandbox.HashExecutable(path)
	require.NoError(t, err)
	assert.Equal(t, expectedHex, got, "SHA-256 digest must match reference value")
	assert.Len(t, got, 64, "hex digest must be 64 characters")
	assert.Equal(t, strings.ToLower(got), got, "hex digest must be lowercase")
}

// TestHashExecutable_MissingFile verifies that HashExecutable returns a
// descriptive error when the file does not exist.
func TestHashExecutable_MissingFile(t *testing.T) {
	_, err := sandbox.HashExecutable("/nonexistent/path/to/binary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open executable for hashing")
}

// TestHashExecutable_StreamsLargeFile verifies that HashExecutable correctly
// handles a file that is larger than a single read buffer (>32 KiB).
func TestHashExecutable_StreamsLargeFile(t *testing.T) {
	dir := t.TempDir()
	// Write 1 MiB of repeating data.
	chunk := bytes.Repeat([]byte("keylatch-sandbox-hash-test"), 1024)
	content := bytes.Repeat(chunk, 40) // ~1 MiB
	path := filepath.Join(dir, "large_exec")
	require.NoError(t, os.WriteFile(path, content, 0o755))

	expected := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(expected[:])

	got, err := sandbox.HashExecutable(path)
	require.NoError(t, err)
	assert.Equal(t, expectedHex, got, "streaming hash must match reference sha256.Sum256")
}

// TestHashExecutable_HashMismatch_RefusesLaunch verifies that sandbox.VerifyExecHash
// returns ErrHashMismatch when the actual digest differs from SandboxManifest.ExecHash,
// which causes RunSandboxed to refuse launch.
func TestHashExecutable_HashMismatch_RefusesLaunch(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/sh\necho world\n")
	path := filepath.Join(dir, "exec")
	require.NoError(t, os.WriteFile(path, content, 0o755))

	m := &sandbox.SandboxManifest{
		ProfileID:  "mismatch-test",
		Executable: path,
		ExecHash:   "0000000000000000000000000000000000000000000000000000000000000000",
	}

	err := sandbox.VerifyExecHash(m)
	require.Error(t, err)
	assert.ErrorIs(t, err, sandbox.ErrHashMismatch,
		"VerifyExecHash must return ErrHashMismatch on digest mismatch")
}
