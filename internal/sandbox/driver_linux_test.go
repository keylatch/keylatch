//go:build linux

package sandbox_test

import (
	"context"
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

// writeFakeExec writes a trivially executable shell script at path and returns
// its SHA-256 hex digest.
func writeFakeExec(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := []byte("#!/bin/sh\nexec \"$@\"\n")
	require.NoError(t, os.WriteFile(path, content, 0o755))
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}

// writeBwrapStub writes a shell script that acts as a bwrap stub: it dumps its
// argv (one arg per line) to a file at the path stored in env var
// BWRAP_ARGV_DUMP, then exits 0.
func writeBwrapStub(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "bwrap")
	content := []byte(`#!/bin/sh
if [ -n "$BWRAP_ARGV_DUMP" ]; then
  for arg in "$@"; do
    printf '%s\n' "$arg" >> "$BWRAP_ARGV_DUMP"
  done
fi
`)
	require.NoError(t, os.WriteFile(path, content, 0o755))
	return path
}

// prependPath prepends dir to PATH and returns a cleanup function.
func prependPath(t *testing.T, dir string) {
	t.Helper()
	old := os.Getenv("PATH")
	t.Setenv("PATH", dir+":"+old)
}

// TestRunSandboxed_FeatureFlagFalse verifies ErrFeatureFlagRequired when flag is off.
func TestRunSandboxed_FeatureFlagFalse(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExec(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	err := sandbox.RunSandboxed(context.Background(), m, false, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrFeatureFlagRequired)
}

// TestRunSandboxed_HashMismatch verifies ErrHashMismatch when exec hash is wrong.
func TestRunSandboxed_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	execPath, _ := writeFakeExec(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   "0000000000000000000000000000000000000000000000000000000000000000",
	}

	err := sandbox.RunSandboxed(context.Background(), m, true, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrHashMismatch)
}

// TestRunSandboxed_ForbiddenMount verifies ErrForbiddenMount when a bind mount
// targets ~/.keylatch.
func TestRunSandboxed_ForbiddenMount(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExec(t, dir, "myexec")
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
		BindMounts: []sandbox.BindMount{
			{Src: filepath.Join(home, ".keylatch"), Dest: "/vault", RO: true},
		},
	}

	err = sandbox.RunSandboxed(context.Background(), m, true, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrForbiddenMount)
}

// TestRunSandboxed_ArgvStructure verifies that bwrap is invoked with the correct
// argument structure: ro-bind, dev, proc, tmpfs, unsetenv HOME, setenv for
// injected vars, and the executable marker "--".
func TestRunSandboxed_ArgvStructure(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExec(t, dir, "myexec")
	bwrapPath := writeBwrapStub(t, dir)

	// Put our fake bwrap first in PATH.
	prependPath(t, dir)

	// Dump file for argv inspection.
	dumpFile := filepath.Join(dir, "argv.txt")
	t.Setenv("BWRAP_ARGV_DUMP", dumpFile)

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
		BindMounts: []sandbox.BindMount{
			{Src: dir, Dest: "/work", RO: false},
		},
		EnvInject: map[string]string{
			"MY_VAR": "hello",
		},
	}

	_ = bwrapPath // stub is found via PATH

	err := sandbox.RunSandboxed(context.Background(), m, true, []string{"EXTRA_VAR=world"}, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(dumpFile)
	require.NoError(t, err)

	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	joined := strings.Join(args, " ")

	// Must have read-only bind for /usr.
	assert.Contains(t, joined, "--ro-bind /usr /usr", "must ro-bind /usr")
	// Must have /bin.
	assert.Contains(t, joined, "--ro-bind /bin /bin", "must ro-bind /bin")
	// Must have --dev /dev.
	assert.Contains(t, joined, "--dev /dev", "must include --dev /dev")
	// Must have --proc /proc.
	assert.Contains(t, joined, "--proc /proc", "must include --proc /proc")
	// Must have --tmpfs /tmp.
	assert.Contains(t, joined, "--tmpfs /tmp", "must include --tmpfs /tmp")
	// Must have the writable bind for the work dir.
	assert.Contains(t, joined, "--bind "+dir+" /work", "must include the manifest bind mount")
	// Must unset HOME.
	assert.Contains(t, joined, "--unsetenv HOME", "must unset HOME")
	// Must inject MY_VAR.
	assert.Contains(t, joined, "--setenv MY_VAR hello", "must inject EnvInject vars")
	// Must inject EXTRA_VAR from extraEnv.
	assert.Contains(t, joined, "--setenv EXTRA_VAR world", "must inject extra env vars")
	// Must end with -- <executable>.
	assert.Contains(t, joined, "-- "+execPath, "must include -- <executable>")
}

// TestRunSandboxed_KeylatchDirAbsent verifies that the bwrap argv does NOT contain
// any reference to ~/.keylatch, even if we pass extraEnv.
func TestRunSandboxed_KeylatchDirAbsent(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExec(t, dir, "myexec")
	writeBwrapStub(t, dir)
	prependPath(t, dir)

	dumpFile := filepath.Join(dir, "argv.txt")
	t.Setenv("BWRAP_ARGV_DUMP", dumpFile)

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	keylatchDir := filepath.Join(home, ".keylatch")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	// Pass a sneaky extraEnv referencing the keylatch dir — it should appear as a
	// value in a --setenv, not as a bind mount. The key invariant is that bwrap
	// does not receive a --bind or --ro-bind targeting ~/.keylatch.
	err = sandbox.RunSandboxed(context.Background(), m, true,
		[]string{"SNEAKY=" + keylatchDir}, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(dumpFile)
	require.NoError(t, err)

	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, a := range args {
		// Ensure no bind mount argument is the keylatch dir.
		if (a == "--bind" || a == "--ro-bind") && i+1 < len(args) {
			src := args[i+1]
			assert.NotEqual(t, keylatchDir, src,
				"bwrap must not receive a bind mount sourcing ~/.keylatch")
		}
	}
}
