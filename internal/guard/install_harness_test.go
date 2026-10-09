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

// harnessFixture is a harness's hooks file location and the stdin payloads it
// sends for a shell command and a file read that the guard must deny.
type harnessFixture struct {
	agent   guard.Agent
	config  string
	payload string
	// readPayload uses {HOME} for the temp home directory; "" = no read hook.
	readPayload string
	// denyKey is a substring of the deny JSON printed on stdout ("" = none).
	denyKey string
	// wantExit is the exit status of a deny.
	wantExit int
	// registrations is how many hook entries carry the guard command.
	registrations int
}

var harnessFixtures = []harnessFixture{
	{guard.AgentCursor, ".cursor/hooks.json", `{"hook_event_name":"beforeShellExecution","command":"direnv export bash","cwd":"/work"}`,
		`{"hook_event_name":"beforeReadFile","file_path":"/work/a.go","content":"","attachments":[{"type":"file","file_path":"{HOME}/.aws/credentials"}]}`, `"permission":"deny"`, 2, 2},
	{guard.AgentWindsurf, ".codeium/windsurf/hooks.json", `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"mise env","cwd":"/work"}}`,
		`{"agent_action_name":"pre_read_code","tool_info":{"file_path":"{HOME}"}}`, "", 2, 2},
	{guard.AgentCodex, ".codex/hooks.json", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"direnv exec . env"}}`, "", `"permissionDecision":"deny"`, 2, 1},
	{guard.AgentCopilot, ".copilot/hooks/keylatch-guard.json", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"atuin search token"}}`, "", `"permissionDecision":"deny"`, 2, 1},
	{guard.AgentGemini, ".gemini/settings.json", `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"printenv"}}`, "", `"decision":"deny"`, 2, 1},
	{guard.AgentAntigravity, ".gemini/config/hooks.json", `{"toolCall":{"name":"run_command","args":{"CommandLine":"atuin history list"}}}`,
		`{"toolCall":{"name":"view_file","args":{"AbsolutePath":"{HOME}/.keylatch/config.yaml"}}}`, `"decision":"deny"`, 0, 1},
}

// runHook runs the installed hook command with payload on stdin.
func runHook(t *testing.T, command, payload string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = strings.NewReader(payload)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "hook failed to run: %v", err)
		code = exitErr.ExitCode()
	}
	return code, stdout.String(), stderr.String()
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
			require.Len(t, commands, fx.registrations)
			assert.Contains(t, commands[0], "--harness "+string(fx.agent))

			code, stdout, stderr := runHook(t, commands[0], fx.payload)
			assert.Equal(t, fx.wantExit, code)
			assert.NotEmpty(t, stderr)
			if fx.denyKey == "" {
				assert.Empty(t, stdout)
			} else {
				assert.Contains(t, stdout, fx.denyKey)
			}

			if fx.readPayload != "" {
				code, stdout, stderr = runHook(t, commands[0], strings.ReplaceAll(fx.readPayload, "{HOME}", home))
				assert.Equal(t, fx.wantExit, code, "read hook must deny")
				assert.NotEmpty(t, stderr)
				if fx.denyKey != "" {
					assert.Contains(t, stdout, fx.denyKey)
				}
				if fx.agent != guard.AgentCursor {
					code, _, _ = runHook(t, commands[0], strings.ReplaceAll(fx.readPayload, "{HOME}", home+"/code/project"))
					assert.Equal(t, 0, code, "unrelated path allowed")
				}
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
	readEntries := cursor["hooks"].(map[string]any)["beforeReadFile"].([]any)
	require.Len(t, readEntries, 1)
	assert.Equal(t, true, readEntries[0].(map[string]any)["failClosed"])
	assert.NoFileExists(t, filepath.Join(home, ".cursor", "settings.json"))

	windsurf := load(".codeium/windsurf/hooks.json")
	assert.Len(t, windsurf["hooks"].(map[string]any)["pre_run_command"], 1)
	assert.Len(t, windsurf["hooks"].(map[string]any)["pre_read_code"], 1)

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
	antiGroup := anti["keylatch-guard"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	assert.Equal(t, "run_command|view_file", antiGroup["matcher"])
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

func TestInstall_CursorUpgradeAddsReadHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	_, err := guard.Install(guard.AgentCursor, guard.InstallOpts{})
	require.NoError(t, err)
	path := filepath.Join(home, ".cursor", "hooks.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(data, &cfg))
	delete(cfg["hooks"].(map[string]any), "beforeReadFile")
	data, err = json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	_, err = guard.Install(guard.AgentCursor, guard.InstallOpts{})
	require.NoError(t, err)
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &cfg))
	hooks := cfg["hooks"].(map[string]any)
	assert.Len(t, hooks["beforeReadFile"], 1)
	assert.Len(t, hooks["beforeShellExecution"], 1)
}
