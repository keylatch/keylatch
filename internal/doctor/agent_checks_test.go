package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/guard"
)

// emptyMachine points the user's home and the Keylatch config at empty
// directories and returns the environment lookup doctor should use.
func emptyMachine(t *testing.T, extra map[string]string) func(string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	cfg := filepath.Join(home, ".keylatch")
	return func(k string) string {
		switch k {
		case "HOME", "USERPROFILE":
			return home
		case "KEYLATCH_CONFIG_DIR":
			return cfg
		case "KEYLATCH_BACKEND":
			return "file"
		}
		return extra[k]
	}
}

func byName(report doctor.Report) map[string]doctor.Status {
	out := map[string]doctor.Status{}
	for _, s := range report.Checks {
		out[s.Name] = s
	}
	return out
}

func TestDoctorRootCauseShortCircuit(t *testing.T) {
	env := emptyMachine(t, nil)
	report, err := doctor.Run(context.Background(), doctor.Options{Env: env, Verbose: true})
	require.NoError(t, err)
	checks := byName(report)

	var failed []string
	for _, s := range report.Checks {
		if !s.OK && !s.Skipped {
			failed = append(failed, s.Name)
		}
	}
	assert.ElementsMatch(t, []string{"bootstrap.keyring", "policy.default_deny"}, failed,
		"a fresh machine shows one FAIL per root cause")

	for _, name := range []string{"bootstrap.config", "audit.writable", "audit.chain", "backend.file", "backend.kek"} {
		s, ok := checks[name]
		require.True(t, ok, "%s must be reported", name)
		assert.True(t, s.Skipped, "%s depends on the bootstrap and must be skipped", name)
		assert.True(t, s.OK, "a skipped check is not a failure")
	}

	for _, s := range report.Checks {
		if s.Fix != "" {
			assert.NotContains(t, s.Fix, "contrib/", "fix hints name commands, never repository paths: %s", s.Name)
		}
	}
}

func TestDoctorDetectsAgent(t *testing.T) {
	env := emptyMachine(t, map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"})
	report, err := doctor.Run(context.Background(), doctor.Options{Env: env})
	require.NoError(t, err)
	assert.True(t, report.AgentSession.Detected)
	assert.Contains(t, report.AgentSession.Signals, "CLAUDECODE")
	assert.Equal(t, "claude-code", report.AgentSession.Harness)

	clean := emptyMachine(t, nil)
	report, err = doctor.Run(context.Background(), doctor.Options{Env: clean})
	require.NoError(t, err)
	assert.False(t, report.AgentSession.Detected)
}

func TestDoctorGuardCurrent(t *testing.T) {
	env := emptyMachine(t, nil)
	home := env("HOME")
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o700))

	run := func() map[string]doctor.Status {
		report, err := doctor.Run(context.Background(), doctor.Options{Env: env, Verbose: true})
		require.NoError(t, err)
		return byName(report)
	}

	// A Claude Code directory with no guard: one root-cause failure, and the
	// version and matcher checks are skipped rather than failing again.
	checks := run()
	assert.False(t, checks["guard.installed"].OK)
	assert.True(t, checks["guard.current"].Skipped)
	assert.True(t, checks["guard.matcher"].Skipped)

	// The installed guard is current and covers every tool.
	_, err := guard.Install(guard.AgentClaudeCode, guard.InstallOpts{})
	require.NoError(t, err)
	checks = run()
	assert.True(t, checks["guard.installed"].OK, checks["guard.installed"].Detail)
	assert.True(t, checks["guard.current"].OK, checks["guard.current"].Detail)
	assert.True(t, checks["guard.matcher"].OK, checks["guard.matcher"].Detail)

	// The shell script of an earlier version fails the currency check with a
	// command as its fix.
	script := filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh")
	settings := filepath.Join(claudeDir, "settings.json")
	require.NoError(t, os.WriteFile(settings,
		[]byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"`+filepath.ToSlash(script)+`"}]}]}}`), 0o600))
	checks = run()
	assert.True(t, checks["guard.installed"].OK)
	assert.False(t, checks["guard.current"].OK)
	assert.Equal(t, "Run `keylatch install-guard claude-code --upgrade` to replace it.", checks["guard.current"].Fix)

	// A guard whose binary is gone fails the same check.
	missing := filepath.ToSlash(filepath.Join(home, "gone", "keylatch"))
	require.NoError(t, os.WriteFile(settings,
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"`+missing+`\" guard hook --harness claude-code"}]}]}}`), 0o600))
	checks = run()
	assert.False(t, checks["guard.current"].OK)
	assert.Contains(t, checks["guard.current"].Detail, missing)

	// A hook that covers only some tools fails the matcher check.
	require.NoError(t, os.WriteFile(settings,
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"`+filepath.ToSlash(script)+`"}]}]}}`), 0o600))
	checks = run()
	assert.False(t, checks["guard.matcher"].OK)
}

func TestDoctorFlagsExportedBackendCredentials(t *testing.T) {
	env := emptyMachine(t, map[string]string{"BW_SESSION": "canary-session-value", "VAULT_TOKEN": "canary-token-value"})
	report, err := doctor.Run(context.Background(), doctor.Options{Env: env, Verbose: true})
	require.NoError(t, err)
	s := byName(report)["env.backend_credentials"]
	assert.True(t, s.Warn)
	assert.Contains(t, s.Detail, "BW_SESSION")
	assert.Contains(t, s.Detail, "VAULT_TOKEN")
	assert.NotContains(t, s.Detail, "canary", "names only, never values")
}
