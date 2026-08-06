package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestLoadConfigOrWarn_MissingConfig verifies a fresh install (no config
// file yet) is silent — nothing to warn about, nothing to back up (M2).
func TestLoadConfigOrWarn_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	got, err := loadConfigOrWarn(cmd, cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.Default(), got)
	require.Empty(t, stderr.String(), "a fresh install must not print a warning")

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Empty(t, matches, "a fresh install must not create a backup file")
}

// TestLoadConfigOrWarn_CorruptConfig verifies a config whose bytes were read
// successfully but are content-unusable (malformed JSON) (a) prints a loud
// warning naming the path and the error, (b) is backed up to
// config.json.bak.<timestamp> using the already-read bytes before being
// reset to defaults, and (c) still returns Default() with a nil error so
// setup can proceed (M2; review finding — blocking: this must NOT fire for
// read/permission errors, see TestLoadConfigOrWarn_PermissionDenied).
func TestLoadConfigOrWarn_CorruptConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	original := []byte("{ this is not valid json")
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	got, err := loadConfigOrWarn(cmd, cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.Default(), got)
	require.Contains(t, stderr.String(), "Warning:")
	require.Contains(t, stderr.String(), cfgPath)

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Len(t, matches, 1, "exactly one backup file must be created")

	backupData, readErr := os.ReadFile(matches[0])
	require.NoError(t, readErr)
	require.Equal(t, original, backupData, "backup must contain the original unreadable content")
}

// TestLoadConfigOrWarn_VersionMismatch verifies a version-mismatched config
// (a readable but unsupported-schema file) triggers the same warn+backup
// path as outright corruption, rather than silently resetting fields (M2).
func TestLoadConfigOrWarn_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data := `{"version":99,"backend":"op","default_namespace":"work","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"}}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(data), 0o600))

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	got, err := loadConfigOrWarn(cmd, cfgPath)
	require.NoError(t, err)
	require.Equal(t, config.Default(), got)
	require.Contains(t, stderr.String(), "Warning:")
	require.Contains(t, stderr.String(), cfgPath)

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Len(t, matches, 1)
}

// TestLoadConfigOrWarn_PermissionDenied verifies the blocking review finding
// is fixed: a config file that exists but cannot be READ (permission denied)
// must NOT be treated like a corrupt file. loadConfigOrWarn must return an
// error, print no "resetting to defaults" warning, write no backup, and
// return a zero Config — callers must abort rather than call config.Save
// over a file they were never able to inspect (config.Save's rename only
// needs directory write permission, so proceeding would silently destroy a
// config that might be perfectly healthy).
func TestLoadConfigOrWarn_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	original := []byte(`{"version":1,"backend":"op","default_namespace":"work","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"}}`)
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	if err := os.Chmod(cfgPath, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o600) })

	// Some environments (e.g. running as root) ignore permission bits — skip
	// rather than false-fail if the file is still readable despite chmod.
	if _, readErr := os.ReadFile(cfgPath); readErr == nil {
		t.Skip("file is still readable despite chmod 0o000 (likely running as root)")
	}

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	got, err := loadConfigOrWarn(cmd, cfgPath)
	require.Error(t, err, "a read/permission failure must abort, not silently reset")
	require.Equal(t, config.Config{}, got)
	require.NotContains(t, stderr.String(), "resetting to defaults", "must not warn about resetting — nothing was reset")

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Empty(t, matches, "a read failure must never produce a backup — the healthy original must be left untouched")

	// The original, healthy file must be completely untouched.
	require.NoError(t, os.Chmod(cfgPath, 0o600))
	stillOriginal, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)
	require.Equal(t, original, stillOriginal, "the original config must survive a read-error abort untouched")
}
