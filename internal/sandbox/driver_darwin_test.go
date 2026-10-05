//go:build darwin

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

// writeFakeExecDarwin writes a trivially executable shell script and returns
// (path, sha256hex).
func writeFakeExecDarwin(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	content := []byte("#!/bin/sh\nexec \"$@\"\n")
	require.NoError(t, os.WriteFile(path, content, 0o755))
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:])
}

// TestRunSandboxedDarwin_FeatureFlagFalse verifies ErrFeatureFlagRequired.
func TestRunSandboxedDarwin_FeatureFlagFalse(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	err := sandbox.RunSandboxed(context.Background(), m, false, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrFeatureFlagRequired)
}

// TestRunSandboxedDarwin_HashMismatch verifies ErrHashMismatch.
func TestRunSandboxedDarwin_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	execPath, _ := writeFakeExecDarwin(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   "0000000000000000000000000000000000000000000000000000000000000000",
	}

	err := sandbox.RunSandboxed(context.Background(), m, true, nil, nil)
	assert.ErrorIs(t, err, sandbox.ErrHashMismatch)
}

// TestRunSandboxedDarwin_ForbiddenMount verifies ErrForbiddenMount.
func TestRunSandboxedDarwin_ForbiddenMount(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")
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

// TestGenerateSbProfile_KeylatchDirDenied verifies that the generated .sb profile
// contains an explicit deny rule for ~/.keylatch.
func TestGenerateSbProfile_KeylatchDirDenied(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	keylatchDir := filepath.Join(home, ".keylatch")

	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	// GenerateSbProfileForTest exposes the generated profile for inspection.
	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)

	// The profile must contain a deny rule referencing ~/.keylatch.
	assert.Contains(t, profile, keylatchDir,
		"sb profile must reference ~/.keylatch in a deny rule")
	assert.True(t,
		strings.Contains(profile, "(deny file-read*") || strings.Contains(profile, "(deny default"),
		"sb profile must have a deny rule")
	// Verify it starts with (version 1).
	assert.True(t, strings.HasPrefix(profile, "(version 1)"),
		"sb profile must start with (version 1)")
}

// TestGenerateSbProfile_ContainsDenyDefault verifies the default-deny stance.
func TestGenerateSbProfile_ContainsDenyDefault(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
	}

	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)

	assert.Contains(t, profile, "(deny default)",
		"sb profile must deny all by default")
}

// TestGenerateSbProfile_BindMountsAllowed verifies that read-write bind mount
// paths appear in the profile with appropriate allow rules.
func TestGenerateSbProfile_BindMountsAllowed(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")

	m := &sandbox.SandboxManifest{
		ProfileID:  "test",
		Executable: execPath,
		ExecHash:   execHash,
		BindMounts: []sandbox.BindMount{
			{Src: dir, Dest: "/work", RO: false},
		},
	}

	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)

	// The writable bind mount path must appear in an allow rule.
	assert.Contains(t, profile, dir,
		"sb profile must include bind mount src path")
}

func TestGenerateSbProfile_DenyPathsFollowAllows(t *testing.T) {
	dir := t.TempDir()
	execPath, execHash := writeFakeExecDarwin(t, dir, "myexec")
	denied := filepath.Join(dir, "secrets")

	m := &sandbox.SandboxManifest{
		Executable: execPath,
		ExecHash:   execHash,
		BindMounts: []sandbox.BindMount{{Src: dir, Dest: dir}},
		Deny:       []string{denied},
	}
	profile, err := sandbox.GenerateSbProfileForTest(m)
	require.NoError(t, err)

	denyRule := `(deny file-read* file-write* (subpath "` + denied + `"))`
	allowRule := `(allow file-read* file-write* (subpath "` + dir + `"))`
	require.Contains(t, profile, denyRule)
	require.Contains(t, profile, allowRule)
	assert.Greater(t, strings.Index(profile, denyRule), strings.LastIndex(profile, "(allow "),
		"deny rules must come after every allow rule so the last matching rule denies")
}

func TestGenerateSbProfile_RelativeDenyRefused(t *testing.T) {
	m := &sandbox.SandboxManifest{Executable: "/usr/bin/true", Deny: []string{"relative"}}
	_, err := sandbox.GenerateSbProfileForTest(m)
	assert.ErrorIs(t, err, sandbox.ErrDenyUnenforceable)
}
