package sandbox_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gdManifestYAML = `profile_id: build
executable: /usr/bin/true
exec_hash: abc
bind_mounts:
  - src: /src
    dest: /work
    ro: true
deny:
  - /secret
env_allowlist: [LANG]
env_inject:
  MODE: ci
`

func gdTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestLoadManifestByProfileID(t *testing.T) {
	home := gdTempHome(t)
	dir := filepath.Join(home, ".keylatch", "sandbox-profiles")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.yaml"), []byte(gdManifestYAML), 0o600))

	m, err := sandbox.LoadManifest("build")
	require.NoError(t, err)
	assert.Equal(t, &sandbox.SandboxManifest{
		ProfileID:    "build",
		Executable:   "/usr/bin/true",
		ExecHash:     "abc",
		BindMounts:   []sandbox.BindMount{{Src: "/src", Dest: "/work", RO: true}},
		Deny:         []string{"/secret"},
		EnvAllowlist: []string{"LANG"},
		EnvInject:    map[string]string{"MODE": "ci"},
	}, m)

	_, err = sandbox.LoadManifest("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read manifest")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("bind_mounts: {nope"), 0o600))
	_, err = sandbox.LoadManifest("bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse manifest")
}

func TestLoadManifestByProfileID_HomeUnset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("os.UserHomeDir fallback differs per OS")
	}
	t.Setenv("HOME", "")
	_, err := sandbox.LoadManifest("build")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get home dir")

	err = sandbox.ValidateBindMounts(&sandbox.SandboxManifest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get home dir")
}

func TestLoadManifestFromExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.yaml")
	require.NoError(t, os.WriteFile(p, []byte(gdManifestYAML), 0o600))
	m, err := sandbox.LoadManifestFromPath(p)
	require.NoError(t, err)
	assert.Equal(t, "build", m.ProfileID)
	assert.Equal(t, map[string]string{"MODE": "ci"}, m.EnvInject)

	_, err = sandbox.LoadManifestFromPath(filepath.Join(dir, "nope.yaml"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))

	require.NoError(t, os.WriteFile(p, []byte("profile_id: [x"), 0o600))
	_, err = sandbox.LoadManifestFromPath(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse manifest")
}

func TestValidateBindMounts_KeylatchDirDenied(t *testing.T) {
	home := gdTempHome(t)
	kl := filepath.Join(home, ".keylatch")
	denied := []sandbox.BindMount{
		{Src: kl, Dest: "/x"},
		{Src: kl + "/", Dest: "/x"},
		{Src: filepath.Join(kl, "vault"), Dest: "/x"},
		{Src: filepath.Join(home, "proj", "..", ".keylatch", "audit"), Dest: "/x"},
		{Src: "/data", Dest: kl},
		{Src: "/data", Dest: filepath.Join(kl, "hooks")},
	}
	for _, bm := range denied {
		err := sandbox.ValidateBindMounts(&sandbox.SandboxManifest{BindMounts: []sandbox.BindMount{{Src: "/ok", Dest: "/ok"}, bm}})
		require.Error(t, err, "%+v", bm)
		assert.ErrorIs(t, err, sandbox.ErrForbiddenMount, "%+v", bm)
	}

	allowed := []sandbox.BindMount{
		{Src: filepath.Join(home, "proj"), Dest: "/work"},
		{Src: filepath.Join(home, ".keylatch-other"), Dest: "/work"},
		{Src: "/usr/share", Dest: "/share", RO: true},
	}
	assert.NoError(t, sandbox.ValidateBindMounts(&sandbox.SandboxManifest{BindMounts: allowed}))
}

func TestVerifyExecHash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	content := []byte("binary-content")
	require.NoError(t, os.WriteFile(p, content, 0o600))
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])

	require.NoError(t, sandbox.VerifyExecHash(&sandbox.SandboxManifest{Executable: p, ExecHash: good}))

	err := sandbox.VerifyExecHash(&sandbox.SandboxManifest{Executable: p, ExecHash: "00" + good[2:]})
	require.ErrorIs(t, err, sandbox.ErrHashMismatch)

	err = sandbox.VerifyExecHash(&sandbox.SandboxManifest{Executable: p, ExecHash: ""})
	require.ErrorIs(t, err, sandbox.ErrHashMismatch, "an empty expected hash must never match")

	err = sandbox.VerifyExecHash(&sandbox.SandboxManifest{Executable: filepath.Join(dir, "gone"), ExecHash: good})
	require.Error(t, err)
	assert.NotErrorIs(t, err, sandbox.ErrHashMismatch)
	assert.Contains(t, err.Error(), "hash verify")
}

func TestHashExecutable_DirectoryFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("opening a directory fails earlier on windows")
	}
	_, err := sandbox.HashExecutable(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash executable")
}
