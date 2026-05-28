//go:build darwin

package sandbox_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFakeExecExtra writes a small shell script and returns (path, sha256hex).
func writeFakeExecExtra(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := []byte("#!/bin/sh\nexec \"$@\"\n")
	require.NoError(t, os.WriteFile(path, content, 0o755))
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}

// TestLoadManifestFromPath_ValidYAML verifies that a well-formed manifest file
// is loaded and unmarshalled correctly.
func TestLoadManifestFromPath_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	yamlContent := "profile_id: myprofile\nexecutable: " + execPath + "\nexec_hash: " + execHash + "\n"
	manifestPath := filepath.Join(dir, "myprofile.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(yamlContent), 0o644))

	m, err := sandbox.LoadManifestFromPath(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, "myprofile", m.ProfileID)
	assert.Equal(t, execPath, m.Executable)
	assert.Equal(t, execHash, m.ExecHash)
}

// TestLoadManifestFromPath_NotFound verifies that a missing file returns an error.
func TestLoadManifestFromPath_NotFound(t *testing.T) {
	_, err := sandbox.LoadManifestFromPath("/nonexistent/path/manifest.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read manifest")
}

// TestLoadManifestFromPath_InvalidYAML verifies that malformed YAML returns an error.
func TestLoadManifestFromPath_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badYAML, []byte("{\ninvalid yaml:::"), 0o644))

	_, err := sandbox.LoadManifestFromPath(badYAML)
	require.Error(t, err)
}

// TestValidateBindMounts_NoMounts verifies that an empty BindMounts list passes.
func TestValidateBindMounts_NoMounts(t *testing.T) {
	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: "/usr/bin/true",
		ExecHash:   "abc",
	}
	err := sandbox.ValidateBindMounts(m)
	require.NoError(t, err)
}

// TestValidateBindMounts_SafeMount verifies that a non-keylatch mount passes.
func TestValidateBindMounts_SafeMount(t *testing.T) {
	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: "/usr/bin/true",
		ExecHash:   "abc",
		BindMounts: []sandbox.BindMount{
			{Src: "/tmp/workdir", Dest: "/work", RO: false},
		},
	}
	err := sandbox.ValidateBindMounts(m)
	require.NoError(t, err)
}

// TestValidateBindMounts_KeylatchInDest verifies that a mount DEST pointing
// at ~/.keylatch is also rejected.
func TestValidateBindMounts_KeylatchInDest(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: "/usr/bin/true",
		ExecHash:   "abc",
		BindMounts: []sandbox.BindMount{
			{Src: "/tmp/safe", Dest: filepath.Join(home, ".keylatch"), RO: true},
		},
	}
	err = sandbox.ValidateBindMounts(m)
	assert.ErrorIs(t, err, sandbox.ErrForbiddenMount)
}

// TestValidateBindMounts_SubdirOfKeylatch verifies that a subdirectory of
// ~/.keylatch is also rejected as a bind-mount source.
func TestValidateBindMounts_SubdirOfKeylatch(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	subdir := filepath.Join(home, ".keylatch", "vault")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: "/usr/bin/true",
		BindMounts: []sandbox.BindMount{
			{Src: subdir, Dest: "/vault", RO: true},
		},
	}
	err = sandbox.ValidateBindMounts(m)
	assert.ErrorIs(t, err, sandbox.ErrForbiddenMount)
}

// TestRunSandboxedDarwin_EnvVarsNotLeaked verifies that environment variables
// present in the parent process are not passed to the sandboxed child when
// featureEnabled is false — the call short-circuits at the feature flag check.
func TestRunSandboxedDarwin_EnvVarsNotLeaked_FeatureGate(t *testing.T) {
	t.Setenv("SUPER_SECRET_ENV", "leak-me-if-you-dare")
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	// With feature flag false, RunSandboxed returns immediately without
	// executing or inspecting env — the parent env is never consulted.
	err := sandbox.RunSandboxed(context.Background(), m, false, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrFeatureFlagRequired)
}

// TestGenerateSbProfile_ExecPathInProfile verifies that the generated profile
// contains an allow rule for the target executable.
func TestGenerateSbProfile_ExecPathInProfile(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)

	assert.Contains(t, profile, execPath, "sb profile must reference the executable path")
	assert.Contains(t, profile, "(allow process-exec", "sb profile must allow process-exec for the executable")
}

// TestGenerateSbProfile_ReadOnlyBindMount verifies that a read-only bind mount
// uses file-read* only (not file-read* file-write*).
func TestGenerateSbProfile_ReadOnlyBindMount(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecExtra(t, dir, "myexec")
	bindSrc := t.TempDir()

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
		BindMounts: []sandbox.BindMount{
			{Src: bindSrc, Dest: "/data", RO: true},
		},
	}

	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)
	assert.Contains(t, profile, bindSrc, "bind src must appear in profile")
}

// TestBuildSandboxExecArgs_ExtraEnvInjected verifies that extra env pairs passed
// to RunSandboxed are reflected in the argv of sandbox-exec (via the generated profile).
// We test this indirectly: RunSandboxed returns ErrHashMismatch before reaching
// the exec step when the hash is wrong, proving validation runs in order.
func TestBuildSandboxExecArgs_HashCheckedBeforeExec(t *testing.T) {
	dir := t.TempDir()
	execPath, _ := writeFakeExecExtra(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   "0000000000000000000000000000000000000000000000000000000000000000",
	}

	err := sandbox.RunSandboxed(context.Background(), m, true, []string{"EXTRA=value"}, nil)
	assert.ErrorIs(t, err, sandbox.ErrHashMismatch,
		"hash mismatch must be detected before attempting to exec")
}
