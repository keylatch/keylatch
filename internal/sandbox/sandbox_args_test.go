//go:build darwin

package sandbox_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildSandboxExecArgs_BasicStructure verifies the argv layout produced by
// buildSandboxExecArgs: -f <profile> env -i [KEY=VAL] <executable>.
func TestBuildSandboxExecArgs_BasicStructure(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	args, err := sandbox.BuildSandboxExecArgsForTest("/tmp/test.sb", m, nil)
	require.NoError(t, err)

	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-f /tmp/test.sb", "must include -f <profile>")
	assert.Contains(t, joined, "env -i", "must include env -i")
	assert.Contains(t, joined, execPath, "must include executable path")
}

// TestBuildSandboxExecArgs_EnvInjectIncluded verifies EnvInject vars appear in argv.
func TestBuildSandboxExecArgs_EnvInjectIncluded(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
		EnvInject:  map[string]string{"MY_VAR": "hello"},
	}

	args, err := sandbox.BuildSandboxExecArgsForTest("/tmp/test.sb", m, nil)
	require.NoError(t, err)

	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "MY_VAR=hello", "EnvInject var must appear in argv")
}

// TestBuildSandboxExecArgs_ExtraEnvIncluded verifies that extra KEY=VALUE pairs
// are appended to the argv.
func TestBuildSandboxExecArgs_ExtraEnvIncluded(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	args, err := sandbox.BuildSandboxExecArgsForTest("/tmp/test.sb", m, []string{"EXTRA=world", "NO_EQUALS_SKIPPED"})
	require.NoError(t, err)

	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "EXTRA=world", "extra env var must appear in argv")
	// Entries without '=' must be skipped.
	assert.NotContains(t, joined, "NO_EQUALS_SKIPPED", "malformed entry without '=' must be skipped")
}

// TestIndexOf_Found verifies indexOf returns the correct position.
func TestIndexOf_Found(t *testing.T) {
	idx := sandbox.IndexOfForTest("KEY=VALUE", '=')
	assert.Equal(t, 3, idx)
}

// TestIndexOf_NotFound verifies indexOf returns -1 when char is absent.
func TestIndexOf_NotFound(t *testing.T) {
	idx := sandbox.IndexOfForTest("NOEQUALS", '=')
	assert.Equal(t, -1, idx)
}

// TestIndexOf_EmptyString verifies indexOf on an empty string returns -1.
func TestIndexOf_EmptyString(t *testing.T) {
	idx := sandbox.IndexOfForTest("", '=')
	assert.Equal(t, -1, idx)
}

// TestIndexOf_FirstChar verifies indexOf finds a byte at position 0.
func TestIndexOf_FirstChar(t *testing.T) {
	idx := sandbox.IndexOfForTest("=VALUE", '=')
	assert.Equal(t, 0, idx)
}
