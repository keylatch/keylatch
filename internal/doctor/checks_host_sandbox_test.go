package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSettings(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
}

func sandboxLookup(t *testing.T, home, project string) func(string) string {
	t.Helper()
	t.Cleanup(doctor.ExportSetManagedSettingsDir(filepath.Join(t.TempDir(), "managed")))
	return makeEnv(map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": project})
}

func TestHostSandboxKeylatchExcluded_UserSettingsRunExcluded_Fails(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json",
		`{"sandbox":{"excludedCommands":["docker:*","${HOME}/.local/bin/keylatch run:*","keylatch call:*"]}}`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.Equal(t, "host.sandbox.keylatch_excluded", st.Name)
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "keylatch run:*")
	assert.Contains(t, st.Fix, "~/.claude/settings.json")
	assert.Contains(t, st.Fix, "sandbox.excludedCommands")
	assert.Contains(t, st.Fix, `"keylatch call:*"`)
	assert.NotContains(t, st.Detail, "docker")
}

func TestHostSandboxKeylatchExcluded_ProjectAndLocalSettings_Fail(t *testing.T) {
	for _, name := range []string{"settings.json", "settings.local.json"} {
		t.Run(name, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			writeSettings(t, filepath.Join(project, ".claude"), name,
				`{"sandbox":{"excludedCommands":["keylatch run:*"]}}`)

			st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

			assert.False(t, st.OK)
			assert.Contains(t, st.Fix, ".claude/"+name)
		})
	}
}

func TestHostSandboxKeylatchExcluded_ConfigDirOverride(t *testing.T) {
	home, project, cfg := t.TempDir(), t.TempDir(), t.TempDir()
	writeSettings(t, cfg, "settings.json", `{"sandbox":{"excludedCommands":["keylatch:*"]}}`)
	lookup := makeEnv(map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": project, "CLAUDE_CONFIG_DIR": cfg})

	t.Cleanup(doctor.ExportSetManagedSettingsDir(filepath.Join(t.TempDir(), "managed")))

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(lookup)(context.Background())

	assert.False(t, st.OK)
}

func TestHostSandboxKeylatchExcluded_ConfigDirSet_IgnoresHomeClaude(t *testing.T) {
	home, project, cfg := t.TempDir(), t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json", `{"sandbox":{"excludedCommands":["keylatch run:*"]}}`)
	lookup := makeEnv(map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": project, "CLAUDE_CONFIG_DIR": cfg})
	t.Cleanup(doctor.ExportSetManagedSettingsDir(filepath.Join(t.TempDir(), "managed")))

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(lookup)(context.Background())

	assert.True(t, st.OK)
	assert.NotContains(t, st.Detail, "run:*")
}

func TestHostSandboxKeylatchExcluded_ManagedSettings_FailWithAdminFix(t *testing.T) {
	home, project, managed := t.TempDir(), t.TempDir(), t.TempDir()
	writeSettings(t, managed, "managed-settings.json", `{"sandbox":{"excludedCommands":["docker:*"]}}`)
	writeSettings(t, filepath.Join(managed, "managed-settings.d"), "10-tools.json", `{"sandbox":{"excludedCommands":["keylatch launch:*"]}}`)
	lookup := makeEnv(map[string]string{"HOME": home, "CLAUDE_PROJECT_DIR": project})
	t.Cleanup(doctor.ExportSetManagedSettingsDir(managed))

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(lookup)(context.Background())

	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, filepath.Join(managed, "managed-settings.d", "10-tools.json"))
	assert.Contains(t, st.Fix, "administrator-managed")
	assert.Contains(t, st.Fix, "ask the administrator")
}

func TestHostSandboxKeylatchExcluded_EntriesAndUnreadableFile_ReportsBoth(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json", `{"sandbox":{"excludedCommands":["keylatch run:*"]}}`)
	writeSettings(t, filepath.Join(project, ".claude"), "settings.json", `{not json`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "keylatch run:*")
	assert.Contains(t, st.Detail, "could not read")
	assert.Contains(t, st.Detail, filepath.Join(project, ".claude", "settings.json"))
}

func TestHostSandboxKeylatchExcluded_PassNamesProjectAndFiles(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json", `{"sandbox":{"excludedCommands":["docker:*"]}}`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, project)
	assert.Contains(t, st.Detail, "~/.claude/settings.json")
}

func TestHostSandboxKeylatchExcluded_OtherVerbsOnly_Warns(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json",
		`{"sandbox":{"excludedCommands":["keylatch call:*","keylatch status:*"]}}`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.True(t, st.OK)
	assert.True(t, st.Warn)
	assert.Contains(t, st.Fix, "sandbox.excludedCommands")
}

func TestHostSandboxKeylatchExcluded_Clean_Passes(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json",
		`{"sandbox":{"excludedCommands":["docker:*"]}}`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	assert.Empty(t, st.Fix)
}

func TestHostSandboxKeylatchExcluded_NoSettingsFiles_Passes(t *testing.T) {
	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, t.TempDir(), t.TempDir()))(context.Background())

	assert.True(t, st.OK)
	assert.False(t, st.Warn)
}

func TestHostSandboxKeylatchExcluded_InvalidJSON_Warns(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json", `{not json`)

	st := doctor.ExportCheckHostSandboxKeylatchExcluded(sandboxLookup(t, home, project))(context.Background())

	assert.True(t, st.OK)
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "could not read")
}

func TestRun_KeylatchExcludedFixtureFailsDoctor(t *testing.T) {
	home, base := bootstrappedHome(t)
	project := t.TempDir()
	lookup := func(k string) string {
		if k == "CLAUDE_PROJECT_DIR" {
			return project
		}
		return base(k)
	}
	t.Cleanup(doctor.ExportSetManagedSettingsDir(filepath.Join(t.TempDir(), "managed")))
	writeSettings(t, filepath.Join(home, ".claude"), "settings.json",
		`{"sandbox":{"excludedCommands":["keylatch run:*"]}}`)

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: lookup, Probe: newMockProbe()})
	require.NoError(t, err)

	assert.False(t, report.OverallOK)
	var found bool
	for _, c := range report.Checks {
		if c.Name == "host.sandbox.keylatch_excluded" {
			found = true
			assert.False(t, c.OK)
		}
	}
	assert.True(t, found)
}

func TestMatchKeylatchExclusion(t *testing.T) {
	tests := []struct {
		pattern   string
		matches   bool
		coversRun bool
	}{
		{"keylatch run:*", true, true},
		{"keylatch:*", true, true},
		{"keylatch", true, true},
		{"keylatch *", true, true},
		{"/usr/local/bin/keylatch run:*", true, true},
		{"${HOME}/.local/bin/keylatch run:*", true, true},
		{"keylatch.exe run:*", true, true},
		{"keylatch run *", true, true},
		{"keylatch launch:*", true, true},
		{"keylatch launch *", true, true},
		{"keylatch --quiet run:*", true, true},
		{"keylatch --json run *", true, true},
		{"keylatch --log-level debug run:*", true, true},
		{"keylatch r*", true, true},
		{"keylatch * run", true, true},
		{"keylatch ?un:*", true, true},
		{"keylatch.EXE run:*", true, true},
		{`C:\tools\keylatch.exe`, true, true},
		{`"C:\Program Files\keylatch\keylatch.exe" run:*`, true, true},
		{`"C:\Program Files\keylatch\keylatch.exe" call:*`, true, false},
		{`"/opt/my apps/keylatch" run:*`, true, true},
		{"~/bin/keylatch run *", true, true},
		{"keylatch unknownverb:*", true, true},
		{"keylatch call:*", true, false},
		{"keylatch doctor", true, false},
		{"keylatchd:*", false, false},
		{"docker:*", false, false},
		{"echo keylatch", false, false},
		{"", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			matches, runs := doctor.ExportMatchKeylatchExclusion(tc.pattern)
			assert.Equal(t, tc.matches, matches)
			assert.Equal(t, tc.coversRun, runs)
		})
	}
}
