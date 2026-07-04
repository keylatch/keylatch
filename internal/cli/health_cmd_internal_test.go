package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envWithConfigDir(dir string) func(string) string {
	return func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
}

func TestCheckHealth_FreshInstall_Healthy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir() // empty — no config, no keyring
	res := checkHealth(envWithConfigDir(dir), false, nil)
	assert.True(t, res.Healthy)
	assert.Contains(t, strings.Join(res.Lines, "\n"), "not bootstrapped")
	assert.Contains(t, res.Lines, "healthy")
}

func TestCheckHealth_BootstrappedAndReadable_Healthy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o600))
	krDir := filepath.Join(dir, "keyring")
	require.NoError(t, os.MkdirAll(krDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(krDir, "keyring.json"), []byte(`{}`), 0o600))

	res := checkHealth(envWithConfigDir(dir), false, nil)
	assert.True(t, res.Healthy)
	assert.Contains(t, res.Lines, "config: ok")
	assert.Contains(t, res.Lines, "keyring: ok")
	assert.Contains(t, res.Lines, "healthy")
}

func TestCheckHealth_UnreadableConfig_Unhealthy(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("running as root — permission bits are not enforced")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sub", "config.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(cfgPath), 0o700))
	require.NoError(t, os.WriteFile(cfgPath, []byte(`{}`), 0o600))
	// Deny traversal into the parent dir so os.Stat(cfgPath) fails with a
	// permission error rather than os.IsNotExist.
	require.NoError(t, os.Chmod(filepath.Dir(cfgPath), 0o000))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(cfgPath), 0o700) })

	env := func(k string) string {
		if k == "KEYLATCH_CONFIG" {
			return cfgPath
		}
		return ""
	}
	res := checkHealth(env, false, nil)
	assert.False(t, res.Healthy)
	assert.Contains(t, res.Lines, "unhealthy")
}

func TestCheckHealth_ProbeServer_NeverFailsHealthOnItsOwn(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	res := checkHealth(envWithConfigDir(dir), true, func() bool { return false })
	assert.True(t, res.Healthy, "an unreachable server must not fail the healthcheck")
	assert.Contains(t, res.Lines, "server: not reachable (informational)")

	res = checkHealth(envWithConfigDir(dir), true, func() bool { return true })
	assert.True(t, res.Healthy)
	assert.Contains(t, res.Lines, "server: reachable")
}

func TestNewHealthCmd_NameIsExactlyHealth(t *testing.T) {
	t.Parallel()
	cmd := newHealthCmd()
	assert.Equal(t, "health", cmd.Use[:len("health")])
	assert.Equal(t, "health", cmd.Name())
}
