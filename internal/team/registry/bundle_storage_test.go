package registry_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	teamregistry "github.com/keylatch/keylatch/internal/team/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxRegDir(t *testing.T) string {
	t.Helper()
	teamDir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", teamDir)
	return filepath.Join(teamDir, "registry")
}

// mxSignedFile signs b with k and writes it to a fresh directory.
func mxSignedFile(t *testing.T, k teamKey, b *teamregistry.InternalBundle) string {
	t.Helper()
	teamregistry.SignBundle(b, k.priv)
	return writeBundleFile(t, t.TempDir(), "bundle.json", b)
}

func mxInstall(t *testing.T, k teamKey, version int64, providers []teamregistry.ProviderTemplate) error {
	t.Helper()
	return teamregistry.Install(context.Background(), mxSignedFile(t, k, newTestBundle(version, providers)), k.pub)
}

func TestVerifyAndInstall_InputErrors(t *testing.T) {
	ctx := context.Background()
	mxRegDir(t)
	k := newKey(t)
	absent := filepath.Join(t.TempDir(), "absent.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))

	for name, fn := range map[string]func(string) error{
		"verify":  func(p string) error { return teamregistry.Verify(ctx, p, k.pub) },
		"install": func(p string) error { return teamregistry.Install(ctx, p, k.pub) },
	} {
		err := fn(absent)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "read", name)
		err = fn(bad)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "parse bundle", name)
	}

	good := mxSignedFile(t, k, newTestBundle(1, nil))
	assert.Error(t, teamregistry.Verify(ctx, good, ""), "a missing key is refused")
	assert.Error(t, teamregistry.Install(ctx, good, ""), "a missing key is refused")
}

func TestList_PicksHighestInstalledVersion(t *testing.T) {
	ctx := context.Background()
	dir := mxRegDir(t)
	k := newKey(t)

	got, err := teamregistry.List(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "no bundle installed means no internal providers")

	require.NoError(t, mxInstall(t, k, 2, []teamregistry.ProviderTemplate{newProvider("old")}))
	require.NoError(t, mxInstall(t, k, 10, []teamregistry.ProviderTemplate{newProvider("new")}))

	// Noise in the directory is ignored.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "99.json"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600))

	got, err = teamregistry.List(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "new", got[0].Provider, "numeric ordering, not lexical: 10 beats 2")

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "10.json"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	assert.ErrorIs(t, mxInstall(t, k, 3, nil), teamregistry.ErrBundleVersionLow)
}

func TestList_EmptyDirAndCorruptLatest(t *testing.T) {
	ctx := context.Background()
	dir := mxRegDir(t)
	k := newKey(t)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	got, err := teamregistry.List(ctx)
	require.NoError(t, err)
	assert.Nil(t, got)

	require.NoError(t, mxInstall(t, k, 1, nil))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "4.json"), []byte("{"), 0o600))
	_, err = teamregistry.List(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse bundle")
}

func TestList_RefusesLatestWithoutPinnedKey(t *testing.T) {
	dir := mxRegDir(t)
	k := newKey(t)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	b := newTestBundle(1, nil)
	teamregistry.SignBundle(b, k.priv)
	writeBundleFile(t, dir, "1.json", b)
	_, err := teamregistry.List(context.Background())
	assert.ErrorIs(t, err, teamregistry.ErrBundleSignatureInvalid)
}

func TestStorageFailures(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	// Registry dir path is a regular file: ReadDir fails.
	teamDir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", teamDir)
	require.NoError(t, os.WriteFile(filepath.Join(teamDir, "registry"), []byte("x"), 0o600))
	_, err := teamregistry.List(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "readdir")

	t.Setenv("KEYLATCH_TEAM_DIR", filepath.Join(blocker, "team"))
	require.Error(t, mxInstall(t, k, 1, nil))

	dir := mxRegDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "7.json.tmp", "occupied"), 0o700))
	err = mxInstall(t, k, 7, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write")
}

func TestRegistryDir_DefaultsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KEYLATCH_TEAM_DIR", "")
	require.NoError(t, mxInstall(t, newKey(t), 1, nil))
	_, err := os.Stat(filepath.Join(home, ".keylatch", "team", "registry", "1.json"))
	assert.NoError(t, err)
}
