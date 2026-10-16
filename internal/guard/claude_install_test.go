package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userSettings = `{
 "permissions": {"allow": ["Bash(go test:*)"], "deny": ["Read(./secrets/**)"]},
 "theme": "dark",
 "hooks": {
  "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "/usr/local/bin/format.sh"}]}],
  "PreToolUse": [
   {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/audit.sh", "timeout": 5}]},
   {"hooks": []}
  ]
 }
}`

// jsonString returns s escaped for use inside a JSON string literal, so a
// Windows path's backslashes survive the payload.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return string(b[1 : len(b)-1])
}

func claudeHome(t *testing.T) (home, bin string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	return home, filepath.Join(t.TempDir(), "keylatch")
}

func guardCommand(bin string) string {
	return `"` + filepath.ToSlash(bin) + `" guard hook --harness claude-code`
}

func TestClaudeInstallMergesExistingHooks(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, userSettings)

	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.True(t, changes[0].Changed)
	assert.Equal(t, settings+".keylatch.bak", changes[0].Backup)

	backup, err := os.ReadFile(changes[0].Backup)
	require.NoError(t, err)
	assert.Equal(t, userSettings, string(backup), "the backup is the file as it was")

	got := readJSON(t, settings)
	assert.Equal(t, "dark", got["theme"])
	assert.JSONEq(t, `{"allow": ["Bash(go test:*)"], "deny": ["Read(./secrets/**)"]}`, string(mustMarshal(t, got["permissions"])))
	hooks := got["hooks"].(map[string]any)
	assert.JSONEq(t, `[{"matcher": "Edit", "hooks": [{"type": "command", "command": "/usr/local/bin/format.sh"}]}]`, string(mustMarshal(t, hooks["PostToolUse"])))
	pre := hooks["PreToolUse"].([]any)
	require.Len(t, pre, 3)
	assert.JSONEq(t, `{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/audit.sh", "timeout": 5}]}`, string(mustMarshal(t, pre[0])))
	assert.JSONEq(t, `{"hooks": []}`, string(mustMarshal(t, pre[1])))
	assert.JSONEq(t, `{"matcher": "*", "hooks": [{"type": "command", "command": `+string(mustMarshal(t, guardCommand(bin)))+`, "timeout": 10}]}`, string(mustMarshal(t, pre[2])))
}

func TestClaudeInstallIdempotent(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, userSettings)
	opts := guard.InstallOpts{KeylatchPath: bin}

	_, err := guard.InstallClaudeCode(opts)
	require.NoError(t, err)
	first, err := os.ReadFile(settings)
	require.NoError(t, err)

	changes, err := guard.InstallClaudeCode(opts)
	require.NoError(t, err)
	assert.False(t, changes[0].Changed, "a second install changes nothing")
	second, err := os.ReadFile(settings)
	require.NoError(t, err)
	assert.Equal(t, string(first), string(second))

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestClaudeInstallCreatesMissingFileWithoutBackup(t *testing.T) {
	home, bin := claudeHome(t)
	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	assert.True(t, changes[0].Changed)
	assert.Empty(t, changes[0].Backup)
	assert.FileExists(t, filepath.Join(home, ".claude", "settings.json"))
	assert.NoFileExists(t, filepath.Join(home, ".claude", "settings.json.keylatch.bak"))
}

func TestClaudeUpgradeReplacesLegacyEntry(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	legacy := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	writeFile(t, settings, `{"hooks":{"PreToolUse":[
 {"matcher":"Edit","hooks":[{"type":"command","command":"/usr/local/bin/first.sh"}]},
 {"hooks":[{"type":"command","command":"`+jsonString(t, legacy)+`"},{"type":"command","command":"/usr/local/bin/same-group.sh"}]},
 {"hooks":[{"type":"command","command":"`+jsonString(t, filepath.Join(home, ".keylatch", "guards", "codex-guard.sh"))+`"}]}
]}}`)

	_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin, Upgrade: true})
	require.NoError(t, err)

	pre := readJSON(t, settings)["hooks"].(map[string]any)["PreToolUse"].([]any)
	var commands []string
	hookCommands(pre, &commands)
	require.Equal(t, []string{guardCommand(bin)}, commands, "legacy script entries are gone and the guard appears once")
	assert.Contains(t, string(mustMarshal(t, pre)), "/usr/local/bin/first.sh")
	assert.Contains(t, string(mustMarshal(t, pre)), "/usr/local/bin/same-group.sh", "another hook sharing the legacy group survives")
	assert.NotContains(t, string(mustMarshal(t, pre)), "block-keylatch-exfiltration")
	assert.NotContains(t, string(mustMarshal(t, pre)), "codex-guard")
}

func TestClaudeUpgradeRefreshesBinaryPathMatcherAndTimeout(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, `{"hooks":{"PreToolUse":[
 {"matcher":"Bash","hooks":[{"type":"command","command":"\"/old/place/keylatch\" guard hook --harness claude-code","timeout":2}]}
]}}`)

	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	assert.False(t, changes[0].Changed, "without --upgrade an installed entry is left as it is")

	changes, err = guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin, Upgrade: true})
	require.NoError(t, err)
	assert.True(t, changes[0].Changed)
	pre := readJSON(t, settings)["hooks"].(map[string]any)["PreToolUse"].([]any)
	require.Len(t, pre, 1, "upgraded in place, not appended")
	group := pre[0].(map[string]any)
	assert.Equal(t, "*", group["matcher"])
	hook := group["hooks"].([]any)[0].(map[string]any)
	assert.Equal(t, guardCommand(bin), hook["command"])
	assert.EqualValues(t, 10, hook["timeout"])

	changes, err = guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin, Upgrade: true})
	require.NoError(t, err)
	assert.False(t, changes[0].Changed, "upgrading twice changes nothing")
}

func TestClaudeUpgradeDropsDuplicateGuardEntries(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	entry := `{"matcher":"*","hooks":[{"type":"command","command":` + string(mustMarshal(t, guardCommand(bin))) + `,"timeout":10}]}`
	writeFile(t, settings, `{"hooks":{"PreToolUse":[`+entry+`,`+entry+`]}}`)

	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	assert.True(t, changes[0].Changed)
	var commands []string
	hookCommands(readJSON(t, settings), &commands)
	assert.Len(t, commands, 1)
}

func TestClaudeConfigDirEnv(t *testing.T) {
	home, bin := claudeHome(t)
	custom := filepath.Join(t.TempDir(), "claude-alt")
	t.Setenv("CLAUDE_CONFIG_DIR", custom)

	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	require.Len(t, changes, 2)
	assert.Equal(t, filepath.Join(home, ".claude", "settings.json"), changes[0].Path)
	assert.Equal(t, filepath.Join(custom, "settings.json"), changes[1].Path)
	for _, c := range changes {
		var commands []string
		hookCommands(readJSON(t, c.Path), &commands)
		assert.Equal(t, []string{guardCommand(bin)}, commands, c.Path)
	}

	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	paths, err := guard.ClaudeSettingsPaths(guard.InstallOpts{})
	require.NoError(t, err)
	assert.Len(t, paths, 1, "the same directory named twice is installed into once")

	extra := filepath.Join(t.TempDir(), "extra")
	paths, err = guard.ClaudeSettingsPaths(guard.InstallOpts{ConfigDirs: []string{extra, " ", extra}})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(extra, "settings.json")}, paths)

	project := t.TempDir()
	paths, err = guard.ClaudeSettingsPaths(guard.InstallOpts{ProjectDir: project, ConfigDirs: []string{extra}})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(project, ".claude", "settings.json")}, paths, "a project install touches only the project")
}

func TestClaudeInstallDryRunWritesNothing(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, userSettings)

	changes, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin, DryRun: true})
	require.NoError(t, err)
	require.True(t, changes[0].Changed)
	assert.Contains(t, changes[0].Diff, "--- "+settings)
	assert.Contains(t, changes[0].Diff, "+++ "+settings+" (after install)")
	assert.Contains(t, changes[0].Diff, "guard hook --harness claude-code")
	assert.Contains(t, changes[0].Diff, "\n+")

	data, err := os.ReadFile(settings)
	require.NoError(t, err)
	assert.Equal(t, userSettings, string(data))
	assert.NoFileExists(t, settings+".keylatch.bak")

	installed, err := guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.False(t, installed)
}

func TestClaudeInstallRefusesMalformedSettings(t *testing.T) {
	home, bin := claudeHome(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	for name, content := range map[string]string{
		"hooks is a string":    `{"hooks":"nope"}`,
		"PreToolUse not array": `{"hooks":{"PreToolUse":{"a":1}}}`,
		"not json":             `{`,
		"top level not object": `[1]`,
	} {
		writeFile(t, settings, content)
		_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
		require.Error(t, err, name)
		data, readErr := os.ReadFile(settings)
		require.NoError(t, readErr)
		assert.Equal(t, content, string(data), name+": the file is untouched")
	}
}

func TestClaudeKeylatchPathWithSpace(t *testing.T) {
	home, _ := claudeHome(t)
	bin := filepath.Join(t.TempDir(), "my tools", "keylatch")
	_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	var commands []string
	hookCommands(readJSON(t, filepath.Join(home, ".claude", "settings.json")), &commands)
	assert.Equal(t, []string{guardCommand(bin)}, commands)
}

func TestClaudeDefaultsToRunningExecutable(t *testing.T) {
	home, _ := claudeHome(t)
	_, err := guard.InstallClaudeCode(guard.InstallOpts{})
	require.NoError(t, err)
	exe, err := os.Executable()
	require.NoError(t, err)
	var commands []string
	hookCommands(readJSON(t, filepath.Join(home, ".claude", "settings.json")), &commands)
	require.Len(t, commands, 1)
	assert.Contains(t, commands[0], filepath.ToSlash(exe))
}

func TestClaudeUninstallRemovesGuardFromEveryConfigDir(t *testing.T) {
	home, bin := claudeHome(t)
	custom := filepath.Join(t.TempDir(), "alt")
	t.Setenv("CLAUDE_CONFIG_DIR", custom)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), userSettings)
	_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: bin})
	require.NoError(t, err)
	legacyScript := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	writeFile(t, legacyScript, "#!/bin/sh\n")

	path, removed, err := guard.Uninstall(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.True(t, removed)
	assert.Equal(t, filepath.Join(home, ".claude", "settings.json"), path)
	for _, p := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(custom, "settings.json")} {
		var commands []string
		hookCommands(readJSON(t, p), &commands)
		assert.Empty(t, commands, p)
	}
	assert.Contains(t, string(mustMarshal(t, readJSON(t, filepath.Join(home, ".claude", "settings.json")))), "audit.sh", "user hooks stay")
	assert.NoFileExists(t, legacyScript)

	_, removed, err = guard.Uninstall(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	assert.False(t, removed)
}
