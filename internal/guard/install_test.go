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

	hooks, ok := settings["hooks"].(map[string]any)
	require.True(t, ok, "hooks must be an object keyed by event name")
	preToolUse, ok := hooks["PreToolUse"].([]any)
	require.True(t, ok, "hooks.PreToolUse must be an array")
	require.Len(t, preToolUse, 1)

	group, ok := preToolUse[0].(map[string]any)
	require.True(t, ok)
	inner, ok := group["hooks"].([]any)
	require.True(t, ok, "matcher group must contain a nested hooks array")
	require.Len(t, inner, 1)
	cmd, ok := inner[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "command", cmd["type"])
	assert.Equal(t, scriptPath, cmd["command"])
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

	hooks, ok := settings["hooks"].(map[string]any)
	require.True(t, ok)
	preToolUse, ok := hooks["PreToolUse"].([]any)
	require.True(t, ok)
	assert.Len(t, preToolUse, 1, "hook must appear exactly once after two install calls")
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

	// Legacy array must be migrated to the object format, preserving the
	// original PostToolUse entry alongside the new PreToolUse entry.
	hooks, ok := settings["hooks"].(map[string]any)
	require.True(t, ok, "legacy array-format hooks must be migrated to object format")
	postToolUse, ok := hooks["PostToolUse"].([]any)
	require.True(t, ok, "pre-existing PostToolUse hook must survive migration")
	assert.Len(t, postToolUse, 1)
	preToolUse, ok := hooks["PreToolUse"].([]any)
	require.True(t, ok)
	assert.Len(t, preToolUse, 1)
}

func TestInstall_ClaudeCode_MigratesLegacyKeylatchHook(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// First install writes the hook; rewrite settings into the legacy
	// array format an older keylatch would have produced.
	settingsPath, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	scriptPath := filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	legacy := map[string]any{
		"hooks": []any{
			map[string]any{
				"event": "PreToolUse",
				"hooks": []any{
					map[string]any{"type": "command", "command": scriptPath},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(legacy, "", "  ")
	require.NoError(t, os.WriteFile(settingsPath, data, 0o600))

	// Re-install must repair the broken legacy format in place, without
	// duplicating the hook.
	_, err = guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	data, err = os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	hooks, ok := settings["hooks"].(map[string]any)
	require.True(t, ok, "legacy keylatch hook must be migrated to object format")
	preToolUse, ok := hooks["PreToolUse"].([]any)
	require.True(t, ok)
	require.Len(t, preToolUse, 1, "migration must not duplicate the keylatch hook")
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

func TestInstall_ClaudeCode_EmptyLegacyHooksArray(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// Settings with an empty legacy hooks array must migrate cleanly and
	// receive the new hook in object format.
	settingsDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	data, _ := json.MarshalIndent(map[string]any{"hooks": []any{}}, "", "  ")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	require.NoError(t, os.WriteFile(settingsPath, data, 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	data, err = os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	hooks, ok := settings["hooks"].(map[string]any)
	require.True(t, ok, "empty legacy array must migrate to object format")
	preToolUse, ok := hooks["PreToolUse"].([]any)
	require.True(t, ok)
	assert.Len(t, preToolUse, 1)
}

func TestInstall_ClaudeCode_NonMigratableLegacyHooksPreserved(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}

	// A legacy array whose entries lack an "event" field cannot be migrated
	// into the object format; install must park them under "hooksLegacy"
	// rather than silently dropping them.
	settingsDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	initial := map[string]any{
		"hooks": []any{
			map[string]any{"command": "/usr/local/bin/eventless-hook.sh"},
		},
	}
	data, _ := json.MarshalIndent(initial, "", "  ")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	require.NoError(t, os.WriteFile(settingsPath, data, 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)

	data, err = os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))

	// The eventless entry must still be present in whatever format resulted.
	assert.Contains(t, string(data), "eventless-hook.sh",
		"non-migratable legacy hook must not be wiped")
}
