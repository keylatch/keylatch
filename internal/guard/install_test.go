package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstall_ClaudeCode_CreatesSettingsAndScript(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	settingsPath, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, ".claude", "settings.json"), settingsPath)

	// Script must exist and be executable (Unix only — Windows has no execute bit).
	scriptPath := filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	info, err := os.Stat(scriptPath)
	require.NoError(t, err, "guard script must exist on disk")
	if runtime.GOOS != "windows" {
		assert.NotZero(t, info.Mode()&0o100, "guard script must be executable")
	}

	// Settings file must contain the hook.
	data, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	hooks, ok := settings["hooks"].([]any)
	require.True(t, ok, "hooks must be an array")
	require.Len(t, hooks, 1)

	entry, ok := hooks[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "PreToolUse", entry["event"])
}

func TestInstall_ClaudeCode_Idempotent(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// First install.
	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	// Second install must not duplicate the hook.
	_, err = guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	hooks, ok := settings["hooks"].([]any)
	require.True(t, ok)
	assert.Len(t, hooks, 1, "hook must appear exactly once after two install calls")
}

func TestInstall_ClaudeCode_IdempotentWithExistingSettings(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// Write a settings file with a pre-existing hook (different command).
	settingsDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	initial := map[string]any{
		"theme": "dark",
		"hooks": []any{
			map[string]any{
				"event": "PostToolUse",
				"hooks": []any{
					map[string]any{"type": "command", "command": "/usr/local/bin/other-hook.sh"},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(initial, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(settingsDir, "settings.json"), data, 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	data, err = os.ReadFile(filepath.Join(settingsDir, "settings.json"))
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	// Original theme preserved.
	assert.Equal(t, "dark", settings["theme"])

	// Should have 2 hook entries: the original PostToolUse + the new PreToolUse.
	hooks, ok := settings["hooks"].([]any)
	require.True(t, ok)
	assert.Len(t, hooks, 2)
}

func TestIsInstalled_ReturnsFalseWhenNotInstalled(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.False(t, installed)
}

func TestIsInstalled_ReturnsTrueAfterInstall(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestInstall_UnsupportedAgent_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// Use a genuinely unsupported agent name (not one of the 9 registered agents).
	_, err := guard.Install("nonexistent-agent-xyz", opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent")
}
