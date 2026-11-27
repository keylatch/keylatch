package guard_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gdHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func gdReadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

func gdWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	data, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func gdAssertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS == "windows" {
		return
	}
	assert.Equal(t, want, info.Mode().Perm(), "mode of %s", path)
}

// gdArrayHookCommands returns the commands of array-format hook entries for event.
func gdArrayHookCommands(t *testing.T, settings map[string]any, event string) []string {
	t.Helper()
	arr, ok := settings["hooks"].([]any)
	require.True(t, ok, "hooks must be an array")
	var out []string
	for _, raw := range arr {
		entry := raw.(map[string]any)
		if entry["event"] != event {
			continue
		}
		for _, h := range entry["hooks"].([]any) {
			hm := h.(map[string]any)
			assert.Equal(t, "command", hm["type"])
			out = append(out, hm["command"].(string))
		}
	}
	return out
}

func gdSkipIfNoPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions required")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func TestEmbeddedScripts_AreShippedWithMarkers(t *testing.T) {
	shells := map[string][]byte{
		"claude":   guard.ClaudeCodeScript,
		"cursor":   guard.CursorScript,
		"aider":    guard.AiderScript,
		"windsurf": guard.WindsurfScript,
		"codex":    guard.CodexScript,
		"copilot":  guard.CopilotScript,
		"gemini":   guard.GeminiScript,
	}
	for name, script := range shells {
		assert.True(t, bytes.HasPrefix(script, []byte("#!/usr/bin/env bash\n")), "%s: shebang", name)
		assert.Contains(t, string(script), "keylatch-hook-version:", "%s: version marker", name)
	}
	assert.Contains(t, string(guard.OpenCodeScript), "tool.execute.before")
}

func TestSupportedAgents_AllHaveHookMechanism(t *testing.T) {
	require.Len(t, guard.SupportedAgents, 9)
	for _, a := range guard.SupportedAgents {
		assert.NotEmpty(t, guard.AgentHookMechanism[a], "agent %s", a)
	}
}

func TestInstall_ClaudeCode_GlobalUsesHome(t *testing.T) {
	home := gdHome(t)

	path, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".claude", "settings.json"), path)

	script := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	gdAssertMode(t, script, 0o700)
	gdAssertMode(t, path, 0o600)
	got, err := os.ReadFile(script)
	require.NoError(t, err)
	assert.Equal(t, guard.ClaudeCodeScript, got)

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestInstall_ClaudeCode_PreservesExistingObjectHooks(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	userGroup := map[string]any{
		"matcher": "Bash",
		"hooks":   []any{map[string]any{"type": "command", "command": "/opt/user-hook.sh"}},
	}
	gdWriteJSON(t, settingsPath, map[string]any{
		"model": "x",
		"hooks": map[string]any{
			"PreToolUse":  []any{userGroup},
			"PostToolUse": []any{map[string]any{"hooks": []any{}}},
		},
	})

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err)

	s := gdReadJSON(t, settingsPath)
	assert.Equal(t, "x", s["model"])
	hooks := s["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	require.Len(t, pre, 2)
	assert.Equal(t, userGroup, pre[0], "user hook must be kept first and untouched")
	assert.Len(t, hooks["PostToolUse"].([]any), 1)
	_, hasLegacy := s["hooksLegacy"]
	assert.False(t, hasLegacy)
}

func TestInstall_ClaudeCode_RecognisesTopLevelCommandEntry(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	script := filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	gdWriteJSON(t, settingsPath, map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{
			"not-an-object",
			map[string]any{"hooks": "not-an-array"},
			map[string]any{"hooks": []any{"not-an-object"}},
			map[string]any{"command": script},
		}},
	})
	before, err := os.ReadFile(settingsPath)
	require.NoError(t, err)

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err)
	assert.True(t, installed)

	_, err = guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err)
	after, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "already-installed settings must not be rewritten")
}

func TestInstall_ClaudeCode_DifferentScriptPathIsNotInstalled(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	gdWriteJSON(t, settingsPath, map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{
			map[string]any{"hooks": []any{map[string]any{"command": "/elsewhere/block-keylatch-exfiltration.sh"}}},
		}},
	})
	installed, err := guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err)
	assert.False(t, installed, "a hook at another path must not count as installed")
}

func TestInstall_ClaudeCode_LegacyNonObjectEntriesParked(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	gdWriteJSON(t, settingsPath, map[string]any{
		"hooks": []any{"bare-string", map[string]any{"event": "Stop", "command": "/opt/stop.sh"}},
	})

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err)

	s := gdReadJSON(t, settingsPath)
	assert.Equal(t, []any{"bare-string"}, s["hooksLegacy"])
	hooks := s["hooks"].(map[string]any)
	stop := hooks["Stop"].([]any)
	require.Len(t, stop, 1)
	assert.Equal(t, map[string]any{"command": "/opt/stop.sh"}, stop[0], "event key must be stripped on migration")
	assert.Len(t, hooks["PreToolUse"].([]any), 1)
}

func TestInstall_ClaudeCode_InvalidSettingsFailsWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settingsPath), 0o700))
	require.NoError(t, os.WriteFile(settingsPath, []byte("{not json"), 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse settings")

	data, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	assert.Equal(t, "{not json", string(data), "corrupt user settings must be left as is")

	_, err = guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse settings")
}

func TestInstall_ClaudeCode_SettingsPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(settingsPath, 0o700))

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read settings")

	_, err = guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read settings")
}

func TestInstall_ClaudeCode_SettingsDirBlockedByFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".claude"), []byte("x"), 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
}

func TestInstall_ClaudeCode_HooksDirBlockedByFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".keylatch"), []byte("x"), 0o600))

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create hooks dir")
	_, statErr := os.Stat(filepath.Join(dir, ".claude", "settings.json"))
	assert.True(t, os.IsNotExist(statErr), "settings must not reference a script that was never written")
}

func TestInstall_ClaudeCode_ScriptPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh"), 0o700))

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write script")
}

func TestInstall_ClaudeCode_SettingsDirReadOnly(t *testing.T) {
	gdSkipIfNoPerms(t)
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	require.NoError(t, os.Chmod(settingsDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(settingsDir, 0o700) })

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create temp settings")
}

func TestInstall_ClaudeCode_LegacyMigrationSaveFailure(t *testing.T) {
	gdSkipIfNoPerms(t)
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, ".claude")
	script := filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	gdWriteJSON(t, filepath.Join(settingsDir, "settings.json"), map[string]any{
		"hooks": []any{map[string]any{
			"event": "PreToolUse",
			"hooks": []any{map[string]any{"type": "command", "command": script}},
		}},
	})
	require.NoError(t, os.Chmod(settingsDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(settingsDir, 0o700) })

	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.Error(t, err, "a legacy hook that cannot be repaired must surface an error")
	assert.Contains(t, err.Error(), "create temp settings")
}

func TestInstall_HomeUnset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("os.UserHomeDir fallback differs per OS")
	}
	t.Setenv("HOME", "")
	for _, a := range []guard.Agent{
		guard.AgentClaudeCode, guard.AgentCursor, guard.AgentAider, guard.AgentCodex,
		guard.AgentCopilot, guard.AgentGemini, guard.AgentOpenCode,
	} {
		_, err := guard.Install(a, guard.InstallOpts{})
		require.Error(t, err, "agent %s", a)
		assert.Contains(t, err.Error(), "home directory", "agent %s", a)
	}
	_, err := guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "home directory")
}

func TestInstall_ClaudeCode_ProjectDirWithHomeUnset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("os.UserHomeDir fallback differs per OS")
	}
	t.Setenv("HOME", "")
	dir := t.TempDir()
	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{ProjectDir: dir})
	require.NoError(t, err, "project-scoped install must not need HOME")
}

func TestIsInstalled_UnknownAgentIsAnError(t *testing.T) {
	ok, err := guard.IsInstalled("bogus", guard.InstallOpts{ProjectDir: t.TempDir()})
	require.Error(t, err)
	assert.False(t, ok)
}

func TestIsInstalled_NotInstalledInFreshHome(t *testing.T) {
	gdHome(t)
	for _, a := range []guard.Agent{guard.AgentClaudeCode, guard.AgentCursor, guard.AgentGemini} {
		ok, err := guard.IsInstalled(a, guard.InstallOpts{})
		require.NoError(t, err, "agent %s", a)
		assert.False(t, ok, "agent %s", a)
	}
}

func TestInstall_ProxyOnlyAgents(t *testing.T) {
	home := gdHome(t)
	for _, a := range []guard.Agent{guard.AgentWindsurf, guard.AgentAntigravity} {
		path, err := guard.Install(a, guard.InstallOpts{})
		require.Error(t, err, "agent %s", a)
		assert.Empty(t, path)
		assert.Contains(t, err.Error(), "hook API")
		assert.Contains(t, err.Error(), "keylatch proxy start")
	}
	entries, err := os.ReadDir(home)
	require.NoError(t, err)
	assert.Empty(t, entries, "unsupported agents must not write anything")
}

func TestInstall_ArrayFormatAgents(t *testing.T) {
	cases := []struct {
		agent    guard.Agent
		rel      []string
		script   string
		content  []byte
		event    string
		altEvent string
	}{
		{guard.AgentCursor, []string{".cursor", "settings.json"}, "cursor-guard.sh", guard.CursorScript, "PreToolUse", ""},
		{guard.AgentCodex, []string{".codex", "hooks.json"}, "codex-guard.sh", guard.CodexScript, "PreToolUse", ""},
		{guard.AgentGemini, []string{".gemini", "settings.json"}, "gemini-guard.sh", guard.GeminiScript, "BeforeTool", ""},
	}
	for _, tc := range cases {
		t.Run(string(tc.agent), func(t *testing.T) {
			home := gdHome(t)
			settingsPath := filepath.Join(append([]string{home}, tc.rel...)...)
			gdWriteJSON(t, settingsPath, map[string]any{
				"keep": true,
				"hooks": []any{map[string]any{
					"event": tc.event,
					"hooks": []any{map[string]any{"type": "command", "command": "/opt/user.sh"}},
				}},
			})

			got, err := guard.Install(tc.agent, guard.InstallOpts{})
			require.NoError(t, err)
			assert.Equal(t, settingsPath, got)

			script := filepath.Join(home, ".keylatch", "hooks", tc.script)
			gdAssertMode(t, script, 0o700)
			body, err := os.ReadFile(script)
			require.NoError(t, err)
			assert.Equal(t, tc.content, body)

			s := gdReadJSON(t, settingsPath)
			assert.Equal(t, true, s["keep"])
			assert.Equal(t, []string{"/opt/user.sh", script}, gdArrayHookCommands(t, s, tc.event))
			gdAssertMode(t, settingsPath, 0o600)

			before, err := os.ReadFile(settingsPath)
			require.NoError(t, err)
			_, err = guard.Install(tc.agent, guard.InstallOpts{})
			require.NoError(t, err)
			after, err := os.ReadFile(settingsPath)
			require.NoError(t, err)
			assert.Equal(t, before, after, "second install must be a no-op")
		})
	}
}

func TestInstall_ArrayFormatAgents_FreshAndErrors(t *testing.T) {
	for _, tc := range []struct {
		agent guard.Agent
		rel   []string
		event string
	}{
		{guard.AgentCursor, []string{".cursor", "settings.json"}, "PreToolUse"},
		{guard.AgentCodex, []string{".codex", "hooks.json"}, "PreToolUse"},
		{guard.AgentGemini, []string{".gemini", "settings.json"}, "BeforeTool"},
	} {
		t.Run(string(tc.agent)+"/fresh", func(t *testing.T) {
			home := gdHome(t)
			path, err := guard.Install(tc.agent, guard.InstallOpts{})
			require.NoError(t, err)
			s := gdReadJSON(t, path)
			assert.Len(t, gdArrayHookCommands(t, s, tc.event), 1)
			assert.Equal(t, filepath.Join(append([]string{home}, tc.rel...)...), path)
		})
		t.Run(string(tc.agent)+"/corrupt", func(t *testing.T) {
			home := gdHome(t)
			p := filepath.Join(append([]string{home}, tc.rel...)...)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
			require.NoError(t, os.WriteFile(p, []byte("[]"), 0o600))
			_, err := guard.Install(tc.agent, guard.InstallOpts{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "parse settings")
		})
		t.Run(string(tc.agent)+"/hooks-dir-blocked", func(t *testing.T) {
			home := gdHome(t)
			require.NoError(t, os.WriteFile(filepath.Join(home, ".keylatch"), nil, 0o600))
			_, err := guard.Install(tc.agent, guard.InstallOpts{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "create hooks dir")
		})
		t.Run(string(tc.agent)+"/save-fails", func(t *testing.T) {
			home := gdHome(t)
			p := filepath.Join(append([]string{home}, tc.rel...)...)
			require.NoError(t, os.WriteFile(filepath.Dir(p), nil, 0o600))
			_, err := guard.Install(tc.agent, guard.InstallOpts{})
			require.Error(t, err)
		})
	}
}

func TestInstall_ProjectDirScriptsLiveInProject(t *testing.T) {
	home := gdHome(t)
	project := t.TempDir()
	path, err := guard.Install(guard.AgentCursor, guard.InstallOpts{ProjectDir: project})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".cursor", "settings.json"), path)
	script := filepath.Join(project, ".keylatch", "hooks", "cursor-guard.sh")
	assert.Equal(t, []string{script}, gdArrayHookCommands(t, gdReadJSON(t, path), "PreToolUse"))
}

func TestInstall_Gemini_AlternateConfigLocation(t *testing.T) {
	home := gdHome(t)
	alt := filepath.Join(home, ".config", "gemini", "settings.json")
	gdWriteJSON(t, alt, map[string]any{})

	path, err := guard.Install(guard.AgentGemini, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Equal(t, alt, path)
	_, statErr := os.Stat(filepath.Join(home, ".gemini", "settings.json"))
	assert.True(t, os.IsNotExist(statErr))
	assert.Len(t, gdArrayHookCommands(t, gdReadJSON(t, alt), "BeforeTool"), 1)
}

func TestInstall_Gemini_PrimaryWinsOverAlternate(t *testing.T) {
	home := gdHome(t)
	primary := filepath.Join(home, ".gemini", "settings.json")
	alt := filepath.Join(home, ".config", "gemini", "settings.json")
	gdWriteJSON(t, primary, map[string]any{})
	gdWriteJSON(t, alt, map[string]any{})

	path, err := guard.Install(guard.AgentGemini, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Equal(t, primary, path)
	assert.Empty(t, gdReadJSON(t, alt))
}

func TestInstall_Aider(t *testing.T) {
	home := gdHome(t)
	conf := filepath.Join(home, ".aider.conf.yml")
	require.NoError(t, os.WriteFile(conf, []byte("model: gpt\r\nauto-commits: false"), 0o600))

	path, err := guard.Install(guard.AgentAider, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Equal(t, conf, path)

	script := filepath.Join(home, ".keylatch", "hooks", "aider-guard.sh")
	gdAssertMode(t, script, 0o700)
	data, err := os.ReadFile(conf)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(data), "model: gpt\r\nauto-commits: false"), "existing config must be kept")
	assert.True(t, strings.HasSuffix(string(data), "\npre-tool-use-hook: "+script+"\n"))

	_, err = guard.Install(guard.AgentAider, guard.InstallOpts{})
	require.NoError(t, err)
	again, err := os.ReadFile(conf)
	require.NoError(t, err)
	assert.Equal(t, data, again, "second install must not append twice")
}

func TestInstall_Aider_CreatesConfigPrivately(t *testing.T) {
	home := gdHome(t)
	path, err := guard.Install(guard.AgentAider, guard.InstallOpts{})
	require.NoError(t, err)
	gdAssertMode(t, path, 0o600)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "\npre-tool-use-hook: "+filepath.Join(home, ".keylatch", "hooks", "aider-guard.sh")+"\n", string(data))
}

func TestInstall_Aider_Errors(t *testing.T) {
	t.Run("config-is-directory", func(t *testing.T) {
		home := gdHome(t)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".aider.conf.yml"), 0o700))
		_, err := guard.Install(guard.AgentAider, guard.InstallOpts{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "open aider config")
	})
	t.Run("hooks-dir-blocked", func(t *testing.T) {
		home := gdHome(t)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".keylatch"), nil, 0o600))
		_, err := guard.Install(guard.AgentAider, guard.InstallOpts{})
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(home, ".aider.conf.yml"))
		assert.True(t, os.IsNotExist(statErr), "config must not point at a script that was never written")
	})
}

func TestInstall_Copilot(t *testing.T) {
	t.Run("bashrc-fallback", func(t *testing.T) {
		home := gdHome(t)
		path, err := guard.Install(guard.AgentCopilot, guard.InstallOpts{})
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(home, ".bashrc"), path)
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr), "rc file must not be created or patched")
		body, err := os.ReadFile(filepath.Join(home, ".keylatch", "hooks", "copilot-guard.sh"))
		require.NoError(t, err)
		assert.Equal(t, guard.CopilotScript, body)
	})
	t.Run("zshrc-preferred", func(t *testing.T) {
		home := gdHome(t)
		zshrc := filepath.Join(home, ".zshrc")
		require.NoError(t, os.WriteFile(zshrc, []byte("# mine\n"), 0o600))
		path, err := guard.Install(guard.AgentCopilot, guard.InstallOpts{})
		require.NoError(t, err)
		assert.Equal(t, zshrc, path)
		data, err := os.ReadFile(zshrc)
		require.NoError(t, err)
		assert.Equal(t, "# mine\n", string(data))
	})
	t.Run("hooks-dir-blocked", func(t *testing.T) {
		home := gdHome(t)
		require.NoError(t, os.WriteFile(filepath.Join(home, ".keylatch"), nil, 0o600))
		_, err := guard.Install(guard.AgentCopilot, guard.InstallOpts{})
		require.Error(t, err)
	})
}

func TestInstall_OpenCode(t *testing.T) {
	home := gdHome(t)
	configPath := filepath.Join(home, ".config", "opencode", "opencode.json")
	gdWriteJSON(t, configPath, map[string]any{"theme": "x", "plugins": []any{"/opt/other.ts", 7}})

	path, err := guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Equal(t, configPath, path)

	plugin := filepath.Join(home, ".config", "opencode", "plugins", "keylatch-guard", "index.ts")
	gdAssertMode(t, plugin, 0o600)
	body, err := os.ReadFile(plugin)
	require.NoError(t, err)
	assert.Equal(t, guard.OpenCodeScript, body)

	s := gdReadJSON(t, configPath)
	assert.Equal(t, "x", s["theme"])
	assert.Equal(t, []any{"/opt/other.ts", float64(7), plugin}, s["plugins"])

	_, err = guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.Len(t, gdReadJSON(t, configPath)["plugins"], 3, "plugin must be registered once")
}

func TestInstall_OpenCode_Errors(t *testing.T) {
	t.Run("plugin-dir-blocked", func(t *testing.T) {
		home := gdHome(t)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".config", "opencode", "plugins"), nil, 0o600))
		_, err := guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create plugin dir")
	})
	t.Run("plugin-file-is-directory", func(t *testing.T) {
		home := gdHome(t)
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "opencode", "plugins", "keylatch-guard", "index.ts"), 0o700))
		_, err := guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "write opencode plugin")
	})
	t.Run("corrupt-config", func(t *testing.T) {
		home := gdHome(t)
		p := filepath.Join(home, ".config", "opencode", "opencode.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte("nope"), 0o600))
		_, err := guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse settings")
	})
	t.Run("config-dir-read-only", func(t *testing.T) {
		gdSkipIfNoPerms(t)
		home := gdHome(t)
		ocDir := filepath.Join(home, ".config", "opencode")
		require.NoError(t, os.MkdirAll(filepath.Join(ocDir, "plugins", "keylatch-guard"), 0o700))
		require.NoError(t, os.Chmod(ocDir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(ocDir, 0o700) })
		_, err := guard.Install(guard.AgentOpenCode, guard.InstallOpts{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create temp settings")
	})
}
