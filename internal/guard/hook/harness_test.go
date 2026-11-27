package hook

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness"
)

func js(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// shellPayload is a shell command in the payload the harness sends.
func shellPayload(harness, cmd string) []byte {
	switch harness {
	case "gemini-cli":
		return js(map[string]any{"tool_name": "run_shell_command", "tool_input": map[string]any{"command": cmd}})
	case "cursor":
		return js(map[string]any{"command": cmd, "cwd": "/work"})
	case "copilot-cli":
		return js(map[string]any{"toolName": "bash", "toolArgs": string(js(map[string]any{"command": cmd}))})
	case "antigravity":
		return js(map[string]any{"toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": cmd}}})
	case "windsurf":
		return js(map[string]any{"agent_action_name": "pre_run_command", "tool_info": map[string]any{"command_line": cmd, "cwd": "/work"}})
	case "opencode":
		return js(map[string]any{"tool_name": "bash", "tool_input": map[string]any{"command": cmd}})
	}
	return bashPayload(cmd)
}

// readPayload is a read of one file in the payload the harness sends.
func readPayload(harness, path string) []byte {
	switch harness {
	case "gemini-cli":
		return js(map[string]any{"tool_name": "read_file", "tool_input": map[string]any{"file_path": path}})
	case "cursor":
		return js(map[string]any{"file_path": path, "attachments": []any{}})
	case "copilot-cli":
		return js(map[string]any{"toolName": "view", "toolArgs": string(js(map[string]any{"path": path}))})
	case "antigravity":
		return js(map[string]any{"toolCall": map[string]any{"name": "view_file", "args": map[string]any{"AbsolutePath": path}}})
	case "windsurf":
		return js(map[string]any{"agent_action_name": "pre_read_code", "tool_info": map[string]any{"file_path": path}})
	case "opencode":
		return js(map[string]any{"tool_name": "read", "tool_input": map[string]any{"filePath": path}})
	}
	return toolPayload("Read", map[string]any{"file_path": path})
}

func run(t *testing.T, harness string, payload []byte) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = RunFor(harness, bytes.NewReader(payload), &out, &errOut, testEnv(t))
	return code, out.String(), errOut.String()
}

func TestAdaptersDenyCorpus(t *testing.T) {
	deny, allow := corpus(t, "deny_corpus.txt"), corpus(t, "allow_corpus.txt")
	require.NotEmpty(t, deny)
	for _, id := range Harnesses() {
		a := adapters[id]
		t.Run(id, func(t *testing.T) {
			for _, cmd := range deny {
				code, stdout, stderr := run(t, id, shellPayload(id, cmd))
				if code != a.exit || !strings.Contains(stderr, "Blocked") {
					t.Fatalf("%s let %q through: exit %d stderr %q", id, cmd, code, stderr)
				}
				if a.denyJSON != nil && !json.Valid([]byte(strings.TrimSpace(stdout))) {
					t.Fatalf("%s: the deny JSON for %q is not JSON: %q", id, cmd, stdout)
				}
			}
			for _, cmd := range allow {
				if code, _, stderr := run(t, id, shellPayload(id, cmd)); code != 0 {
					t.Fatalf("%s blocked %q: %s", id, cmd, stderr)
				}
			}
		})
	}
}

func TestAdaptersDenyCredentialReads(t *testing.T) {
	for _, id := range Harnesses() {
		t.Run(id, func(t *testing.T) {
			code, _, stderr := run(t, id, readPayload(id, testHome+"/.ssh/id_rsa"))
			assert.Equal(t, adapters[id].exit, code, stderr)
			assert.Contains(t, stderr, "Blocked")
			code, _, stderr = run(t, id, readPayload(id, "/work/src/main.go"))
			assert.Equal(t, 0, code, stderr)
		})
	}
}

func TestDenyContractPerHarness(t *testing.T) {
	for id, want := range map[string]struct {
		exit int
		key  string
	}{
		"claude-code": {2, "hookSpecificOutput"}, "codex": {2, "hookSpecificOutput"},
		"gemini-cli": {2, "decision"}, "antigravity": {0, "decision"}, "cursor": {2, "permission"},
		"copilot-cli": {2, "permissionDecision"}, "windsurf": {2, ""}, "opencode": {2, ""},
	} {
		code, stdout, _ := run(t, id, shellPayload(id, "env"))
		assert.Equal(t, want.exit, code, id)
		if want.key == "" {
			assert.Empty(t, strings.TrimSpace(stdout), id)
			continue
		}
		var v map[string]any
		require.NoError(t, json.Unmarshal([]byte(stdout), &v), id)
		assert.Contains(t, v, want.key, id)
	}
	code, stdout, _ := run(t, "cursor", shellPayload("cursor", "ls"))
	assert.Equal(t, 0, code)
	assert.JSONEq(t, `{"permission":"allow"}`, stdout, "Cursor and Gemini expect an explicit allow")
}

func TestAdaptersFailClosed(t *testing.T) {
	garbage := [][]byte{[]byte("not json"), []byte("{}"), []byte(`{"toolCall":{}}`), []byte(`{"agent_action_name":"post_run_command"}`), []byte(`{"file_path":5,"command":5}`)}
	for _, id := range Harnesses() {
		for _, payload := range garbage {
			code, _, _ := run(t, id, payload)
			assert.Equal(t, adapters[id].exit, code, "%s: %q must be denied", id, payload)
		}
	}
	code, _, stderr := run(t, "vim", shellPayload("claude-code", "ls"))
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "unsupported harness")
	assert.True(t, DecideFor("vim", nil, testEnv(t)).Deny)
}

func TestCursorMCPAndAttachments(t *testing.T) {
	env := testEnv(t)
	mcp := js(map[string]any{"tool_name": "fetch", "tool_input": string(js(map[string]any{"path": testHome + "/.aws/credentials"}))})
	assert.True(t, DecideFor("cursor", mcp, env).Deny, "an MCP call naming a credential file is denied")
	object := js(map[string]any{"tool_name": "fetch", "tool_input": map[string]any{"path": testHome + "/.aws/credentials"}})
	assert.True(t, DecideFor("cursor", object, env).Deny)
	assert.False(t, DecideFor("cursor", js(map[string]any{"tool_name": "fetch", "tool_input": map[string]any{"url": "https://example.com"}}), env).Deny)
	attach := js(map[string]any{"file_path": "/work/a.go", "attachments": []any{map[string]any{"type": "file", "file_path": testHome + "/.ssh/id_rsa"}}})
	assert.True(t, DecideFor("cursor", attach, env).Deny, "an attached credential file is denied")
	assert.True(t, DecideFor("cursor", js(map[string]any{"tool_name": "Shell", "tool_input": map[string]any{"command": "printenv"}}), env).Deny)
}

func TestWindsurfActions(t *testing.T) {
	env := testEnv(t)
	write := js(map[string]any{"agent_action_name": "pre_write_code", "tool_info": map[string]any{"file_path": testHome + "/.codeium/windsurf/hooks.json"}})
	assert.True(t, DecideFor("windsurf", write, env).Deny, "a write to the hook file is denied")
	mcp := js(map[string]any{"agent_action_name": "pre_mcp_tool_use", "tool_info": map[string]any{
		"mcp_server_name": "files", "mcp_tool_name": "read", "mcp_tool_arguments": map[string]any{"path": testHome + "/.ssh/id_rsa"},
	}})
	assert.True(t, DecideFor("windsurf", mcp, env).Deny)
	noArgs := js(map[string]any{"agent_action_name": "pre_mcp_tool_use", "tool_info": map[string]any{"mcp_server_name": "files", "mcp_tool_name": "list"}})
	assert.False(t, DecideFor("windsurf", noArgs, env).Deny)
}

func TestHookFilesAreProtectedFromEveryHarness(t *testing.T) {
	env := testEnv(t)
	for _, p := range []string{
		"/.claude/settings.json", "/.claude/settings.local.json", "/.cursor/hooks.json", "/.codex/hooks.json", "/.codex/config.toml",
		"/.gemini/settings.json", "/.config/opencode/opencode.json", "/.config/opencode/plugins/keylatch-guard.ts",
		"/.copilot/hooks/keylatch-guard.json", "/.codeium/windsurf/hooks.json", "/.gemini/config/hooks.json", "/.claude.json",
	} {
		d := DecideFor("claude-code", toolPayload("Write", map[string]any{"file_path": testHome + p}), env)
		assert.True(t, d.Deny, "%s must be protected", p)
	}
}

func TestHarnessesAreTheRegistrysAdapters(t *testing.T) {
	var want []string
	for _, d := range harness.Installable() {
		want = append(want, d.Adapter)
	}
	sort.Strings(want)
	assert.Equal(t, want, Harnesses(), "every installable harness has an adapter and every adapter an installable harness")
}
