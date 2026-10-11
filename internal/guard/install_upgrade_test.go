package guard_test

import (
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

func setHome(t *testing.T, home string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(home, 0o700))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("COPILOT_HOME", "")
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o700))
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestInstall_HookCommandSurvivesSpaceInHome(t *testing.T) {
	payloads := map[guard.Agent]string{
		guard.AgentCursor:      `{"hook_event_name":"beforeShellExecution","command":"keylatch get x y","cwd":"/work"}`,
		guard.AgentWindsurf:    `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"keylatch get x y"}}`,
		guard.AgentAntigravity: `{"toolCall":{"name":"run_command","args":{"CommandLine":"keylatch get x y"}}}`,
		guard.AgentGemini:      `{"tool_name":"run_shell_command","tool_input":{"command":"keylatch get x y"}}`,
	}
	for _, agent := range []guard.Agent{guard.AgentClaudeCode, guard.AgentCodex, guard.AgentGemini, guard.AgentCursor, guard.AgentWindsurf, guard.AgentCopilot, guard.AgentAntigravity} {
		t.Run(string(agent), func(t *testing.T) {
			setHome(t, filepath.Join(t.TempDir(), "h o me"))
			path, err := guard.Install(agent, guard.InstallOpts{})
			require.NoError(t, err)

			var commands []string
			hookCommands(readJSON(t, path), &commands)
			require.NotEmpty(t, commands)
			assert.Contains(t, commands[0], `"`)

			payload, ok := payloads[agent]
			if !ok {
				payload = `{"tool_name":"Bash","tool_input":{"command":"keylatch get x y"}}`
			}
			code, stdout, stderr := runHook(t, commands[0], payload)
			assert.NotEqual(t, 127, code, "hook command must find the script: %s", stderr)
			if agent == guard.AgentAntigravity {
				assert.Contains(t, stdout, `"decision":"deny"`)
			} else {
				assert.Equal(t, 2, code, "stderr: %s", stderr)
			}
		})
	}
}

func TestInstall_ClaudeCodeReplacesBareCommand(t *testing.T) {
	dir := t.TempDir()
	opts := guard.InstallOpts{ProjectDir: dir}
	scriptPath := filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	settingsPath := filepath.Join(dir, ".claude", "settings.json")
	bare := mustMarshal(t, map[string]any{"hooks": map[string]any{"PreToolUse": []any{
		map[string]any{"hooks": []any{map[string]any{"type": "command", "command": scriptPath}}},
		map[string]any{"matcher": "Edit", "hooks": []any{map[string]any{"type": "command", "command": "/usr/local/bin/other.sh"}}},
	}}})
	writeFile(t, settingsPath, string(bare))

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.False(t, installed, "a bare-path entry is not the current command")

	for range 2 {
		_, err = guard.Install(guard.AgentClaudeCode, opts)
		require.NoError(t, err)
	}

	cfg := readJSON(t, settingsPath)
	var commands []string
	hookCommands(cfg, &commands)
	require.Len(t, commands, 1, "the bare entry is replaced, not duplicated")
	assert.NotEqual(t, scriptPath, commands[0])
	assert.Contains(t, string(mustMarshal(t, cfg)), "/usr/local/bin/other.sh")
	assert.Len(t, cfg["hooks"].(map[string]any)["PreToolUse"], 2)

	installed, err = guard.IsInstalled(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.True(t, installed)
	if runtime.GOOS != "windows" {
		assert.Equal(t, `"`+scriptPath+`"`, commands[0])
	}
}

func TestInstall_RemovesOldPerAgentGuards(t *testing.T) {
	cases := []struct {
		agent  guard.Agent
		config string
		legacy func(t *testing.T, home string) string
	}{
		{guard.AgentCodex, ".codex/hooks.json", func(t *testing.T, home string) string {
			return `{"hooks":[{"event":"PreToolUse","matcher":".*","hooks":[{"type":"command","command":"` + jsonString(t, filepath.Join(home, ".keylatch", "guards", "codex-guard.sh")) + `"}]}]}`
		}},
		{guard.AgentGemini, ".gemini/settings.json", func(t *testing.T, home string) string {
			return `{"theme":"dark","hooks":[{"event":"BeforeTool","type":"command","command":"` + jsonString(t, filepath.Join(home, ".keylatch", "hooks", "gemini-guard.sh")) + `"}]}`
		}},
	}
	for _, tc := range cases {
		t.Run(string(tc.agent), func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "home")
			setHome(t, home)
			oldScripts := []string{
				filepath.Join(home, ".keylatch", "hooks", string(tc.agent)+"-guard.sh"),
				filepath.Join(home, ".keylatch", "guards", string(tc.agent)+"-guard.sh"),
			}
			for _, p := range oldScripts {
				writeFile(t, p, "#!/bin/sh\n")
			}
			other := filepath.Join(home, ".keylatch", "hooks", "cursor-guard.sh")
			writeFile(t, other, "#!/bin/sh\n")
			config := filepath.Join(home, filepath.FromSlash(tc.config))
			writeFile(t, config, tc.legacy(t, home))

			for range 2 {
				_, err := guard.Install(tc.agent, guard.InstallOpts{})
				require.NoError(t, err)
			}

			data, err := os.ReadFile(config)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "-guard.sh")
			var commands []string
			hookCommands(readJSON(t, config), &commands)
			assert.Len(t, commands, 1)
			for _, p := range oldScripts {
				assert.NoFileExists(t, p)
			}
			assert.FileExists(t, other, "another agent's old script stays until that agent is upgraded")
			if tc.agent == guard.AgentGemini {
				assert.Contains(t, string(data), `"theme"`)
			}
		})
	}
}

func TestInstall_CursorRemovesOldSettingsEntry(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	oldScript := filepath.Join(home, ".keylatch", "guards", "cursor-guard.sh")
	writeFile(t, oldScript, "#!/bin/sh\n")
	settings := filepath.Join(home, ".cursor", "settings.json")
	writeFile(t, settings, `{"editor":"x","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"`+jsonString(t, oldScript)+`"}]}]}}`)

	_, err := guard.Install(guard.AgentCursor, guard.InstallOpts{})
	require.NoError(t, err)

	data, err := os.ReadFile(settings)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "cursor-guard.sh")
	assert.Contains(t, string(data), `"editor"`)
	assert.NotContains(t, string(data), `"hooks"`)
	assert.NoFileExists(t, oldScript)
	assert.FileExists(t, filepath.Join(home, ".cursor", "hooks.json"))
}

func TestInstall_GeminiUpgradeWidensMatcher(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	path, err := guard.Install(guard.AgentGemini, guard.InstallOpts{})
	require.NoError(t, err)

	cfg := readJSON(t, path)
	group := cfg["hooks"].(map[string]any)["BeforeTool"].([]any)[0].(map[string]any)
	group["matcher"] = "run_shell_command|read_file|read_many_files"
	require.NoError(t, os.WriteFile(path, mustMarshal(t, cfg), 0o600))

	_, err = guard.Install(guard.AgentGemini, guard.InstallOpts{})
	require.NoError(t, err)
	groups := readJSON(t, path)["hooks"].(map[string]any)["BeforeTool"].([]any)
	require.Len(t, groups, 1)
	matcher := groups[0].(map[string]any)["matcher"].(string)
	for _, tool := range []string{"read_many_files", "glob", "search_file_content"} {
		assert.True(t, strings.Contains(matcher, tool), "matcher %q must include %s", matcher, tool)
	}
}
