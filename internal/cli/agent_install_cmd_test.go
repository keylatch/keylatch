package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness"
)

func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, v := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME", "XDG_CONFIG_HOME"} {
		t.Setenv(v, "")
	}
	return home
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		rel, _ := filepath.Rel(root, path)
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	return out
}

func TestAgentInstallMatchesInstallGuard(t *testing.T) {
	var trees [2]map[string]string
	for i, args := range [][]string{
		{"agent", "install", "claude-code", "--guard"},
		{"install-guard", "claude-code", "--guard"},
	} {
		home := isolatedHome(t)
		_, errOut, code := runCLI(t, "", args...)
		require.Equal(t, 0, code, errOut)
		trees[i] = readTree(t, home)
		require.Contains(t, trees[i], ".claude/settings.json")
	}
	assert.Equal(t, trees[0], trees[1], "both spellings write the same bytes")
}

func TestDeprecatedAliasesWarn(t *testing.T) {
	isolatedHome(t)
	_, errOut, code := runCLI(t, "", "install-guard", "claude-code", "--dry-run")
	assert.Equal(t, 0, code)
	assert.Contains(t, errOut, "deprecated")
	assert.Contains(t, errOut, "keylatch agent install")

	_, errOut, code = runCLI(t, "", "agent", "setup", "claude-code", "--dry-run")
	assert.Equal(t, 0, code)
	assert.Contains(t, errOut, "deprecated")

	_, errOut, _ = runCLI(t, "", "agent", "install", "claude-code", "--dry-run")
	assert.NotContains(t, errOut, "deprecated", "the new command does not warn")
}

func TestLaunchOnlyHarnessesEditNothing(t *testing.T) {
	for _, name := range []string{"aider", "goose"} {
		t.Run(name, func(t *testing.T) {
			home := isolatedHome(t)
			out, errOut, code := runCLI(t, "", "agent", "install", name)
			require.Equal(t, 0, code, errOut)
			assert.Contains(t, out, "keylatch launch -- "+name)
			assert.Empty(t, readTree(t, home), "no file is written")

			out, _, code = runCLI(t, "", "agent", "uninstall", name)
			assert.Equal(t, 0, code)
			assert.Contains(t, out, "nothing to remove")
		})
	}
}

func TestHarnessDocsMatchRegistry(t *testing.T) {
	labels := map[harness.Support]string{
		harness.SupportGuard: "guard plus detection", harness.SupportDetect: "detection only", harness.SupportLaunchOnly: "launch only",
	}
	index, err := os.ReadFile(filepath.Join("..", "..", "docs", "harnesses", "index.md"))
	require.NoError(t, err)
	pages := map[string]bool{"index.md": true}
	for _, d := range harness.All() {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "harnesses", d.ID+".md"))
		require.NoError(t, err, "every harness has a page")
		pages[d.ID+".md"] = true
		page := strings.ReplaceAll(string(data), "\r\n", "\n")
		assert.Contains(t, page, "harness: "+d.ID)
		assert.Contains(t, page, "Support level: "+labels[d.Support], d.ID)
		assert.Contains(t, string(index), "("+d.ID+".md)", "the index links %s", d.ID)
		if d.Support == harness.SupportGuard {
			assert.Contains(t, page, d.HookDisplay(), "%s page names its hook file", d.ID)
			for _, event := range d.Hook.Events {
				assert.Contains(t, page, event, "%s page names the %s event", d.ID, event)
			}
			assert.Contains(t, page, "guard hook --harness "+d.Adapter)
			assert.Contains(t, page, filepath.ToSlash(d.MCP.File[strings.LastIndex(d.MCP.File, "/")+1:]), "%s page names its MCP file", d.ID)
		} else {
			assert.Contains(t, page, "keylatch launch -- "+d.Executables[0])
		}
	}
	entries, err := os.ReadDir(filepath.Join("..", "..", "docs", "harnesses"))
	require.NoError(t, err)
	for _, e := range entries {
		assert.True(t, pages[e.Name()], "%s documents no harness in the registry", e.Name())
	}
}

func TestAgentInstallAllUsesWhatIsFound(t *testing.T) {
	home := isolatedHome(t)
	t.Setenv("PATH", t.TempDir())
	_, errOut, code := runCLI(t, "", "agent", "install", "--all")
	assert.NotEqual(t, 0, code, "nothing is installed here")
	assert.Contains(t, errOut, "no supported agent harness")

	require.NoError(t, os.MkdirAll(filepath.Join(home, ".codex"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".cursor"), 0o700))
	out, errOut, code := runCLI(t, "", "agent", "install", "--all")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "== Codex CLI")
	assert.Contains(t, out, "== Cursor")
	assert.NotContains(t, out, "Windsurf")
	tree := readTree(t, home)
	assert.Contains(t, tree, ".codex/hooks.json")
	assert.Contains(t, tree, ".cursor/hooks.json")
	assert.NotContains(t, tree, ".gemini/settings.json")
	assert.Contains(t, out, "cursorignore", "the Cursor note is shown")

	_, _, code = runCLI(t, "", "agent", "install", "codex", "--all")
	assert.NotEqual(t, 0, code, "a name and --all together are ambiguous")
	_, errOut, code = runCLI(t, "", "agent", "install")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, errOut, "name a harness")
	_, errOut, code = runCLI(t, "", "agent", "install", "emacs")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, errOut, "unknown harness")
}

func TestAgentInstallPartsDryRunProjectAndUninstall(t *testing.T) {
	home := isolatedHome(t)
	out, _, code := runCLI(t, "", "agent", "install", "codex", "--mcp", "--dry-run")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "[mcp_servers.keylatch]")
	assert.Empty(t, readTree(t, home))

	out, errOut, code := runCLI(t, "", "agent", "install", "codex", "--mcp", "--rules")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "MCP server written to")
	tree := readTree(t, home)
	assert.Contains(t, tree, ".codex/config.toml")
	assert.Contains(t, tree, ".codex/AGENTS.md")
	assert.NotContains(t, tree, ".codex/hooks.json", "the guard was not asked for")

	out, _, code = runCLI(t, "", "agent", "install", "codex", "--mcp")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "already installed")

	out, errOut, code = runCLI(t, "", "agent", "uninstall", "codex", "--dry-run")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "mcp_servers.keylatch", "the diff shows the removal")
	assert.Contains(t, readTree(t, home)[".codex/config.toml"], "mcp_servers.keylatch")

	out, errOut, code = runCLI(t, "", "agent", "uninstall", "codex")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "removed from Codex CLI")
	assert.NotContains(t, readTree(t, home)[".codex/config.toml"], "keylatch")
	out, _, code = runCLI(t, "", "agent", "uninstall", "codex")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "No Keylatch integration found")

	proj := t.TempDir()
	t.Chdir(proj)
	_, errOut, code = runCLI(t, "", "agent", "install", "cursor", "--project", "--guard", "--rules")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, readTree(t, proj), ".cursor/hooks.json")
	assert.Contains(t, readTree(t, proj), ".cursor/rules/keylatch.mdc")
}

func TestInstallGuardListNamesEveryHarness(t *testing.T) {
	out, _, code := runCLI(t, "", "install-guard", "--list")
	require.Equal(t, 0, code)
	for _, d := range harness.All() {
		if d.Support != harness.SupportDetect {
			assert.Contains(t, out, d.ID)
		}
	}
	_, errOut, code := runCLI(t, "", "install-guard", "aider")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, errOut, "no hook API")
}
