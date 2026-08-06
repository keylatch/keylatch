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

	got := loadConfigOrWarn(cmd, cfgPath)
	require.Equal(t, config.Default(), got)
	require.Empty(t, stderr.String(), "a fresh install must not print a warning")

	matches, err := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, err)
	require.Empty(t, matches, "a fresh install must not create a backup file")
}

// TestLoadConfigOrWarn_CorruptConfig verifies an unreadable/corrupt config
// (a) prints a loud warning naming the path and the error, (b) is backed up
// to config.json.bak.<timestamp> before being reset to defaults, and (c)
// still returns Default() so setup can proceed (M2).
func TestLoadConfigOrWarn_CorruptConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	original := []byte("{ this is not valid json")
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetErr(&stderr)

	got := loadConfigOrWarn(cmd, cfgPath)
	require.Equal(t, config.Default(), got)
	require.Contains(t, stderr.String(), "Warning:")
	require.Contains(t, stderr.String(), cfgPath)

	matches, err := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, err)
	require.Len(t, matches, 1, "exactly one backup file must be created")

	backupData, err := os.ReadFile(matches[0])
	require.NoError(t, err)
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

	got := loadConfigOrWarn(cmd, cfgPath)
	require.Equal(t, config.Default(), got)
	require.Contains(t, stderr.String(), "Warning:")
	require.Contains(t, stderr.String(), cfgPath)

	matches, err := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, err)
	require.Len(t, matches, 1)
}
