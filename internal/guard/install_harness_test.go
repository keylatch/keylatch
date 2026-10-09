package guard_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// harnessFixture is a harness's hooks file location and the stdin payload it
// sends for a shell command that the guard must deny.
type harnessFixture struct {
	agent   guard.Agent
	config  string
	payload string
	// denyKey is a substring of the deny JSON printed on stdout ("" = none).
	denyKey string
}

var harnessFixtures = []harnessFixture{
	{guard.AgentCursor, ".cursor/hooks.json", `{"hook_event_name":"beforeShellExecution","command":"direnv export bash","cwd":"/work"}`, `"permission":"deny"`},
	{guard.AgentWindsurf, ".codeium/windsurf/hooks.json", `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"mise env","cwd":"/work"}}`, ""},
	{guard.AgentCodex, ".codex/hooks.json", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"direnv exec . env"}}`, `"permissionDecision":"deny"`},
	{guard.AgentCopilot, ".copilot/hooks/keylatch-guard.json", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"atuin search token"}}`, `"permissionDecision":"deny"`},
	{guard.AgentGemini, ".gemini/settings.json", `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"printenv"}}`, `"decision":"deny"`},
	{guard.AgentAntigravity, ".gemini/config/hooks.json", `{"toolCall":{"name":"run_command","args":{"CommandLine":"atuin history list"}}}`, `"decision":"deny"`},
}

func hookCommands(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "block-keylatch-exfiltration.sh") {
			*out = append(*out, t)
		}
	case []any:
		for _, e := range t {
			hookCommands(e, out)
		}
	case map[string]any:
		for _, e := range t {
			hookCommands(e, out)
		}
	}
}

func TestInstall_HarnessHooksBlockWithRealPayload(t *testing.T) {
	for _, fx := range harnessFixtures {
		t.Run(string(fx.agent), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("COPILOT_HOME", "")

			path, err := guard.Install(fx.agent, guard.InstallOpts{})
			require.NoError(t, err)
			assert.Equal(t, filepath.Join(home, filepath.FromSlash(fx.config)), path)

			installed, err := guard.IsInstalled(fx.agent, guard.InstallOpts{})
			require.NoError(t, err)
			assert.True(t, installed)

			// A second install must not register the hook twice.
			_, err = guard.Install(fx.agent, guard.InstallOpts{})
			require.NoError(t, err)

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var cfg map[string]any
			require.NoError(t, json.Unmarshal(data, &cfg))
			var commands []string
			hookCommands(cfg, &commands)
			require.Len(t, commands, 1, "hook registered exactly once")
			assert.Contains(t, commands[0], "--harness "+string(fx.agent))

			cmd := exec.Command("sh", "-c", commands[0])
			cmd.Stdin = strings.NewReader(fx.payload)
			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			var exitErr *exec.ExitError
			require.True(t, errors.As(err, &exitErr), "guard must exit non-zero, got %v", err)
			assert.Equal(t, 2, exitErr.ExitCode())
			assert.NotEmpty(t, stderr.String())
			if fx.denyKey == "" {
				assert.Empty(t, stdout.String())
			} else {
				assert.Contains(t, stdout.String(), fx.denyKey)
			}
		})
	}
}

func TestInstall_HarnessHookSchemas(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("COPILOT_HOME", "")

	load := func(rel string) map[string]any {
		data, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(rel)))
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(data, &m))
		return m
	}

	for _, a := range []guard.Agent{guard.AgentCursor, guard.AgentWindsurf, guard.AgentCodex, guard.AgentCopilot, guard.AgentGemini, guard.AgentAntigravity} {
		_, err := guard.Install(a, guard.InstallOpts{})
		require.NoError(t, err)
	}

	cursor := load(".cursor/hooks.json")
	assert.EqualValues(t, 1, cursor["version"])
	entries := cursor["hooks"].(map[string]any)["beforeShellExecution"].([]any)
	require.Len(t, entries, 1)
	assert.Equal(t, true, entries[0].(map[string]any)["failClosed"])
	assert.NoFileExists(t, filepath.Join(home, ".cursor", "settings.json"))

	windsurf := load(".codeium/windsurf/hooks.json")
	assert.Len(t, windsurf["hooks"].(map[string]any)["pre_run_command"], 1)

	codex := load(".codex/hooks.json")
	group := codex["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	assert.Equal(t, "Bash", group["matcher"])

	gemini := load(".gemini/settings.json")
	group = gemini["hooks"].(map[string]any)["BeforeTool"].([]any)[0].(map[string]any)
	assert.Contains(t, group["matcher"], "run_shell_command")

	copilot := load(".copilot/hooks/keylatch-guard.json")
	entry := copilot["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	assert.Contains(t, entry["bash"], "--harness copilot")

	anti := load(".gemini/config/hooks.json")
	assert.Equal(t, true, anti["keylatch-guard"].(map[string]any)["enabled"])
}

func TestInstall_HarnessPreservesExistingHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	path := filepath.Join(home, ".cursor", "hooks.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"hooks":{"beforeShellExecution":[{"command":"./audit.sh"}],"stop":[{"command":"./done.sh"}]}}`), 0o600))

	_, err := guard.Install(guard.AgentCursor, guard.InstallOpts{})
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))
	hooks := cfg["hooks"].(map[string]any)
	assert.Len(t, hooks["beforeShellExecution"], 2)
	assert.Len(t, hooks["stop"], 1)
}

func TestInstall_AiderIsUnsupported(t *testing.T) {
	_, err := guard.Install("aider", guard.InstallOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported agent")
}
