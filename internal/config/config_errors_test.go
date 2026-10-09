package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorMessages(t *testing.T) {
	assert.Equal(t, "bw: folder and collection are mutually exclusive; set only one", config.ErrBWMutualExclusion{}.Error())
	assert.Equal(t, "config version mismatch: got 7, want 1", (&config.VersionMismatch{Got: 7, Want: 1}).Error())

	err := config.ValidateSetKey("github.API_Token")
	var blocked *config.BlockedConfigKey
	require.True(t, errors.As(err, &blocked))
	assert.Equal(t, "token", blocked.Matched)
	assert.Contains(t, err.Error(), `config key "github.API_Token" looks like a credential`)
	assert.Contains(t, err.Error(), "keylatch set")
}

func TestBWConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.BWConfig
		wantErr string
	}{
		{"empty ok", config.BWConfig{}, ""},
		{"https ok", config.BWConfig{Server: "https://vault.example.invalid", Folder: "f"}, ""},
		{"plain http rejected", config.BWConfig{Server: "http://vault.example.invalid"}, "must use https://"},
		{"folder and collection", config.BWConfig{Folder: "f", Collection: "c"}, "mutually exclusive"},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if tc.wantErr == "" {
			assert.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			assert.Contains(t, err.Error(), tc.wantErr, tc.name)
		}
	}
}

func TestLoad_RejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}

	_, err := config.Load(filepath.Join(dir, "missing.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read config")

	_, err = config.Load(write("unknown.json", `{"version":1,"surprise":true}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode config")

	_, err = config.Load(write("retention.json", `{"version":1,"audit":{"retention_days":9999}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retention_days=9999")

	_, err = config.Load(write("sweep.json", `{"version":1,"audit":{"sweep_interval_hours":-1}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sweep_interval_hours")
}

func TestSave_FailuresLeaveNoTempFiles(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "new", "dir", "config.json")
	require.NoError(t, config.Save(nested, config.Default()))
	info, err := os.Stat(filepath.Dir(nested))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "a missing config directory is created owner-only")
	}

	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	err = config.Save(filepath.Join(blocker, "config.json"), config.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create config directory")

	// Renaming onto an existing non-empty directory fails; the temp file
	// must be cleaned up.
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "occupied"), 0o700))
	err = config.Save(target, config.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename temp config")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".config-"), "leftover temp file %s", e.Name())
	}
}
