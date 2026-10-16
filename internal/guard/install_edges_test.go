package guard_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScriptVersion(t *testing.T) {
	assert.Equal(t, 3, guard.ScriptVersion([]byte("#!/bin/sh\n# keylatch-hook-version: 3\nexit 0\n")))
	assert.Equal(t, 0, guard.ScriptVersion([]byte("#!/bin/sh\n# keylatch-hook-version: three\n")))
	assert.Equal(t, 0, guard.ScriptVersion([]byte("#!/bin/sh\nexit 0\n")))
	assert.Positive(t, guard.ClaudeCodeVersion())
	assert.Equal(t, guard.ScriptVersion(guard.GuardScript), guard.ClaudeCodeVersion())
}

func TestProtectedPathsFromScript(t *testing.T) {
	assert.Contains(t, guard.ProtectedPaths(), ".ssh")
	saved := guard.GuardScript
	t.Cleanup(func() { guard.GuardScript = saved })
	guard.GuardScript = []byte("no list here")
	assert.Nil(t, guard.ProtectedPaths())
}

func TestEveryAgentInstallsDetectsAndUninstalls(t *testing.T) {
	for _, agent := range guard.SupportedAgents {
		t.Run(string(agent), func(t *testing.T) {
			setHome(t, filepath.Join(t.TempDir(), "home"))
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			opts := guard.InstallOpts{KeylatchPath: filepath.Join(t.TempDir(), "keylatch")}

			ok, err := guard.IsInstalled(agent, opts)
			require.NoError(t, err)
			assert.False(t, ok)

			_, err = guard.Install(agent, opts)
			require.NoError(t, err)
			ok, err = guard.IsInstalled(agent, opts)
			require.NoError(t, err)
			assert.True(t, ok)

			_, removed, err := guard.Uninstall(agent, opts)
			require.NoError(t, err)
			assert.True(t, removed)
			ok, err = guard.IsInstalled(agent, opts)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestUnsupportedAgentIsRefused(t *testing.T) {
	setHome(t, t.TempDir())
	_, err := guard.IsInstalled("nope", guard.InstallOpts{})
	assert.ErrorContains(t, err, "unsupported agent")
	_, _, err = guard.Uninstall("nope", guard.InstallOpts{})
	assert.ErrorContains(t, err, "unsupported agent")
}

func TestInstallFailsWithoutAUsableHome(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	for _, agent := range guard.SupportedAgents {
		t.Run("home is a file/"+string(agent), func(t *testing.T) {
			t.Setenv("HOME", file)
			t.Setenv("USERPROFILE", file)
			t.Setenv("COPILOT_HOME", "")
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			_, err := guard.Install(agent, guard.InstallOpts{KeylatchPath: "/opt/keylatch"})
			assert.Error(t, err)
			_, _, err = guard.Uninstall(agent, guard.InstallOpts{})
			// Windows reports a path below a file as not found rather than not a
			// directory, so uninstall finds nothing to remove there.
			if agent != agentOpenCode && runtime.GOOS != "windows" {
				assert.Error(t, err)
			}
		})
		t.Run("home unset/"+string(agent), func(t *testing.T) {
			t.Setenv("HOME", "")
			t.Setenv("USERPROFILE", "")
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			_, err := guard.Install(agent, guard.InstallOpts{KeylatchPath: "/opt/keylatch"})
			assert.Error(t, err)
			_, err = guard.IsInstalled(agent, guard.InstallOpts{})
			assert.Error(t, err)
			_, _, err = guard.Uninstall(agent, guard.InstallOpts{})
			assert.Error(t, err)
		})
	}
}

func TestUnreadableSettingsFailTheInstall(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	settings := filepath.Join(home, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(settings, 0o700), "a directory where the file should be")

	_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: "/opt/keylatch"})
	assert.Error(t, err)
	_, err = guard.IsInstalled(guard.AgentClaudeCode, guard.InstallOpts{})
	assert.Error(t, err)
	_, _, err = guard.Uninstall(guard.AgentClaudeCode, guard.InstallOpts{})
	assert.Error(t, err)
}

func TestInstallFailsWhenTheBackupCannotBeWritten(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, `{"theme":"dark"}`)
	require.NoError(t, os.MkdirAll(settings+".keylatch.bak", 0o700), "a directory where the backup should be")

	_, err := guard.InstallClaudeCode(guard.InstallOpts{KeylatchPath: "/opt/keylatch"})
	assert.ErrorContains(t, err, "backup")
	data, readErr := os.ReadFile(settings)
	require.NoError(t, readErr)
	assert.JSONEq(t, `{"theme":"dark"}`, string(data), "the settings are untouched when the backup fails")
}

func TestUninstallLeavesOtherHarnessEntries(t *testing.T) {
	setHome(t, filepath.Join(t.TempDir(), "home"))
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	opts := guard.InstallOpts{KeylatchPath: "/opt/keylatch"}
	for _, a := range []guard.Agent{guard.AgentClaudeCode, agentGemini, agentAntigravity} {
		_, err := guard.Install(a, opts)
		require.NoError(t, err)
	}
	_, removed, err := guard.Uninstall(agentAntigravity, opts)
	require.NoError(t, err)
	assert.True(t, removed)
	ok, err := guard.IsInstalled(agentGemini, opts)
	require.NoError(t, err)
	assert.True(t, ok, "removing one harness leaves the others")
}

func TestUninstallKeepsTheOldScriptWhileAHookStillRunsIt(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	setHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	script := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	writeFile(t, script, "#!/bin/sh\n")
	writeFile(t, filepath.Join(home, ".cursor", "hooks.json"),
		`{"version":1,"hooks":{"beforeShellExecution":[{"command":"`+jsonString(t, script)+` --harness cursor"}]}}`)
	opts := guard.InstallOpts{KeylatchPath: "/opt/keylatch"}
	_, err := guard.Install(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	_, _, err = guard.Uninstall(guard.AgentClaudeCode, opts)
	require.NoError(t, err)
	assert.FileExists(t, script, "a Cursor hook still runs the script")

	_, err = guard.Install(agentCursor, opts)
	require.NoError(t, err)
	assert.NoFileExists(t, script, "once no hook runs it the script goes")
}
