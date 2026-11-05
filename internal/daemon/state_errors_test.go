package daemon_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadState_Errors(t *testing.T) {
	dir := t.TempDir()

	_, err := daemon.LoadState(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read daemon state")

	corrupt := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{first_launch_done:"), 0o600))
	s, err := daemon.LoadState(corrupt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse daemon state")
	assert.False(t, s.FirstLaunchDone, "corrupt state must read as not-yet-launched")
}

func TestLoadState_IgnoresUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(p, []byte(`{"first_launch_done":true,"extra":1}`), 0o600))
	s, err := daemon.LoadState(p)
	require.NoError(t, err)
	assert.True(t, s.FirstLaunchDone)
}

func TestSaveState_Errors(t *testing.T) {
	t.Run("missing parent dir", func(t *testing.T) {
		err := daemon.SaveState(filepath.Join(t.TempDir(), "nope", "state.json"), daemon.State{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create temp daemon state")
	})
	t.Run("target is a non-empty directory", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "state.json")
		require.NoError(t, os.MkdirAll(filepath.Join(target, "child"), 0o700))

		err := daemon.SaveState(target, daemon.State{FirstLaunchDone: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rename daemon state")

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "temp file %s must be removed on failure", e.Name())
		}
	})
}

func TestSaveState_WritesExactJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, daemon.SaveState(p, daemon.State{FirstLaunchDone: true}))
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "{\n \"first_launch_done\": true\n}\n", string(data))
}
