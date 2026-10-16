package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCLI runs the root command with stdin and returns stdout, stderr and the
// exit status main would use.
func runCLI(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	root := cli.NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	code := cli.ReportError(root, args, err, &errOut)
	return out.String(), errOut.String(), code
}

func bashCall(t *testing.T, command string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
	require.NoError(t, err)
	return string(b)
}

func TestGuardHookDeniesWithExitTwoAndJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	out, errOut, code := runCLI(t, bashCall(t, "cat ~/.ssh/id_rsa"), "guard", "hook", "--harness", "claude-code")
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "[hook/keylatch] Blocked:")
	var resp struct {
		Out struct {
			Decision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, "deny", resp.Out.Decision)

	out, errOut, code = runCLI(t, bashCall(t, "go test ./..."), "guard", "hook", "--harness", "claude-code")
	assert.Equal(t, 0, code)
	assert.Empty(t, out)
	assert.Empty(t, errOut)
}

func TestGuardHookFailsClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, c := range map[string]struct {
		stdin string
		args  []string
	}{
		"unparsable command": {bashCall(t, "echo 'oops"), []string{"guard", "hook", "--harness", "claude-code"}},
		"not json":           {"{", []string{"guard", "hook", "--harness", "claude-code"}},
		"unknown harness":    {bashCall(t, "ls"), []string{"guard", "hook", "--harness", "emacs"}},
		"no harness":         {bashCall(t, "ls"), []string{"guard", "hook"}},
	} {
		_, errOut, code := runCLI(t, c.stdin, c.args...)
		assert.Equal(t, 2, code, name)
		assert.NotEmpty(t, errOut, name)
	}
}

func TestGuardHookSkipsRootInitialisation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KEYLATCH_CONFIG_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	_, _, code := runCLI(t, bashCall(t, "ls"), "guard", "hook", "--harness", "claude-code", "--log-level", "debug")
	assert.Equal(t, 0, code)
}

func TestInstallGuardClaudeFlags(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	settings := filepath.Join(home, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settings), 0o700))
	original := `{"theme":"dark"}`
	require.NoError(t, os.WriteFile(settings, []byte(original), 0o600))

	out, _, code := runCLI(t, "", "install-guard", "claude-code", "--dry-run")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "guard hook --harness claude-code")
	assert.Contains(t, out, "+++ "+settings)
	data, err := os.ReadFile(settings)
	require.NoError(t, err)
	assert.Equal(t, original, string(data), "a dry run writes nothing")

	extra := filepath.Join(t.TempDir(), "alt")
	out, _, code = runCLI(t, "", "install-guard", "claude-code", "--config-dir", extra)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "previous file saved as "+settings+".keylatch.bak")
	assert.Contains(t, out, "Hook written to: "+filepath.Join(extra, "settings.json"))
	assert.Contains(t, out, "keylatch doctor")
	assert.FileExists(t, filepath.Join(extra, "settings.json"))

	out, _, code = runCLI(t, "", "install-guard", "claude-code", "--config-dir", extra)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "already installed")
	assert.Contains(t, out, "--upgrade")

	out, _, code = runCLI(t, "", "install-guard", "claude-code", "--upgrade")
	assert.Equal(t, 0, code)
	assert.NotContains(t, out, "Hook written", "an upgrade with nothing to change writes nothing")

	out, _, code = runCLI(t, "", "install-guard", "cursor", "--dry-run")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "guard hook --harness cursor")
	assert.NoFileExists(t, filepath.Join(home, ".cursor", "hooks.json"), "a dry run writes nothing")
	_, errOut, code := runCLI(t, "", "install-guard", "codex", "--config-dir", extra)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, errOut, "claude-code only")
}
