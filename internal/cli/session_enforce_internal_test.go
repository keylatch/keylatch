package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withOperatorHome(t *testing.T, home string) {
	t.Helper()
	prev := operatorHome
	operatorHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { operatorHome = prev })
}

func writeOptInConfig(t *testing.T, path string, allow bool, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	cfg := config.Default()
	cfg.AllowUnverifiedSession = allow
	require.NoError(t, config.Save(path, cfg))
	require.NoError(t, os.Chmod(path, mode))
}

func TestOptInReadFromDefaultConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withOperatorHome(t, home)
	path := paths.DefaultConfig(home)

	assert.False(t, configAllowsUnverifiedSession(), "no config file")

	writeOptInConfig(t, path, false, 0o600)
	assert.False(t, configAllowsUnverifiedSession(), "opt-in not set")

	writeOptInConfig(t, path, true, 0o600)
	assert.True(t, configAllowsUnverifiedSession(), "opt-in in the operator's own config")
}

func TestOptInIgnoresConfigOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withOperatorHome(t, home)

	elsewhere := t.TempDir()
	redirected := filepath.Join(elsewhere, "config.json")
	writeOptInConfig(t, redirected, true, 0o600)
	writeOptInConfig(t, filepath.Join(elsewhere, "keylatch", "config.json"), true, 0o600)

	for name, set := range map[string]func(){
		"KEYLATCH_CONFIG":     func() { t.Setenv("KEYLATCH_CONFIG", redirected) },
		"KEYLATCH_CONFIG_DIR": func() { t.Setenv("KEYLATCH_CONFIG_DIR", elsewhere) },
		"XDG_CONFIG_HOME":     func() { t.Setenv("XDG_CONFIG_HOME", elsewhere) },
	} {
		t.Run(name, func(t *testing.T) {
			set()
			assert.False(t, configAllowsUnverifiedSession(), "%s must not redirect the opt-in", name)
		})
	}
}

func TestOptInIgnoresHomeVariable(t *testing.T) {
	operator := t.TempDir()
	withOperatorHome(t, operator)
	planted := t.TempDir()
	writeOptInConfig(t, paths.DefaultConfig(planted), true, 0o600)
	t.Setenv("HOME", planted)
	t.Setenv("USERPROFILE", planted)

	assert.False(t, configAllowsUnverifiedSession(), "HOME must not redirect the opt-in")
}

func TestOptInRefusesWritableOrLinkedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no mode bits or symlink-free default here")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withOperatorHome(t, home)
	path := paths.DefaultConfig(home)

	writeOptInConfig(t, path, true, 0o666)
	assert.False(t, configAllowsUnverifiedSession(), "world-writable config")

	writeOptInConfig(t, path, true, 0o620)
	assert.False(t, configAllowsUnverifiedSession(), "group-writable config")

	target := filepath.Join(t.TempDir(), "config.json")
	writeOptInConfig(t, target, true, 0o600)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink(target, path))
	assert.False(t, configAllowsUnverifiedSession(), "symlinked config")
}
