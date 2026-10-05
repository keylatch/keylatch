package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cbHookCommands(t *testing.T, settingsPath string) []string {
	t.Helper()
	data, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))
	var cmds []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if c, ok := x["command"].(string); ok {
				cmds = append(cmds, c)
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(settings["hooks"])
	return cmds
}

func TestInstallGuard_ClaudeCodeGlobalMergesSettingsIdempotently(t *testing.T) {
	cbIsolate(t)
	home := os.Getenv("HOME")
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settingsPath), 0o700))
	require.NoError(t, os.WriteFile(settingsPath, []byte(`{"theme":"dark"}`), 0o600))

	out, _, err := cbRun(t, "install-guard", "Claude_Code")
	require.NoError(t, err)
	assert.Contains(t, out, "Guard installed for Claude Code.")
	assert.Contains(t, out, "Hook written to: "+settingsPath)
	assert.Contains(t, out, "To verify: keylatch doctor")

	script := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	assert.Equal(t, os.FileMode(0o700), cbMode(t, script))
	assert.Equal(t, os.FileMode(0o700), cbMode(t, filepath.Dir(script)))

	data, err := os.ReadFile(settingsPath)
	require.NoError(t, err)
	var settings map[string]any
	require.NoError(t, json.Unmarshal(data, &settings))
	assert.Equal(t, "dark", settings["theme"], "existing settings must be preserved")
	cmds := cbHookCommands(t, settingsPath)
	require.Len(t, cmds, 1)
	assert.Contains(t, cmds[0], script)

	_, _, err = cbRun(t, "install-guard", "claude-code")
	require.NoError(t, err)
	assert.Len(t, cbHookCommands(t, settingsPath), 1, "re-install must not duplicate the hook")
}

func TestInstallGuard_ClaudeCodeProjectScope(t *testing.T) {
	cbIsolate(t)
	dir := t.TempDir()
	t.Chdir(dir)

	out, _, err := cbRun(t, "install-guard", "claudecode", "--project")
	require.NoError(t, err)
	assert.Contains(t, out, filepath.Join(".claude", "settings.json"))
	assert.FileExists(t, filepath.Join(dir, ".keylatch", "hooks", "block-keylatch-exfiltration.sh"))
	require.Len(t, cbHookCommands(t, filepath.Join(dir, ".claude", "settings.json")), 1)
	_, statErr := os.Stat(filepath.Join(os.Getenv("HOME"), ".claude", "settings.json"))
	assert.True(t, os.IsNotExist(statErr), "--project must not touch the global settings")
}

func TestInstallGuard_OtherAgentsWriteTheirConfig(t *testing.T) {
	cases := []struct {
		agent   string
		banner  string
		relPath string
	}{
		{"cursor", "Guard installed for Cursor.", ".cursor/settings.json"},
		{"aider", "Guard installed for Aider.", ".aider.conf.yml"},
		{"codex", "Guard installed for Codex CLI.", ".codex/hooks.json"},
		{"gemini", "Guard installed for Gemini CLI.", ""},
		{"opencode", "Guard installed for OpenCode.", ".config/opencode/opencode.json"},
		{"copilot", "Installing shell wrapper", ""},
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			cbIsolate(t)
			home := os.Getenv("HOME")
			t.Setenv("SHELL", "/bin/bash")

			out, _, err := cbRun(t, "install-guard", tc.agent)
			require.NoError(t, err)
			assert.Contains(t, out, tc.banner)
			if tc.relPath != "" {
				p := filepath.Join(home, filepath.FromSlash(tc.relPath))
				assert.FileExists(t, p)
				assert.Contains(t, out, p)
			}
			if tc.agent == "copilot" {
				// The wrapper script is installed; the reported rc file is only a
				// suggestion and is not modified.
				assert.FileExists(t, filepath.Join(home, ".keylatch", "hooks", "copilot-guard.sh"))
				assert.Contains(t, out, "Shell RC patched: "+filepath.Join(home, ".bashrc"))
				return
			}
			for _, line := range strings.Split(out, "\n") {
				_, path, ok := strings.Cut(line, ": ")
				if ok && strings.HasPrefix(path, home) {
					assert.FileExists(t, path)
				}
			}
		})
	}
}

func TestInstallGuard_ManualAgentsWriteNothing(t *testing.T) {
	for _, agent := range []string{"windsurf", "antigravity"} {
		t.Run(agent, func(t *testing.T) {
			cbIsolate(t)
			out, _, err := cbRun(t, "install-guard", agent)
			require.NoError(t, err)
			assert.Contains(t, out, "export CREDENTIALS_LLM_SESSION="+agent)
			entries, err := os.ReadDir(os.Getenv("HOME"))
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

func TestInstallGuard_Refusals(t *testing.T) {
	cbIsolate(t)

	_, _, err := cbRun(t, "install-guard")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent name required")

	_, _, err = cbRun(t, "install-guard", "notepad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown agent "notepad"`)
	assert.Contains(t, err.Error(), "claude-code")

	out, _, err := cbRun(t, "install-guard", "--list")
	require.NoError(t, err)
	assert.Contains(t, out, "Supported agents for keylatch install-guard:")
}

func TestInstallGuard_InstallErrorSurfaces(t *testing.T) {
	cbIsolate(t)
	home := os.Getenv("HOME")
	require.NoError(t, os.WriteFile(filepath.Join(home, ".keylatch"), nil, 0o600))

	_, _, err := cbRun(t, "install-guard", "claude-code")
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "install-guard: "), err.Error())
}
