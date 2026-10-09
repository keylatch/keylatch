package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigCmd_SetGetListPersist(t *testing.T) {
	cfgDir := cbIsolate(t)
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))

	out, _, err := cbRun(t, "config", "get", "backend")
	require.NoError(t, err)
	assert.Equal(t, config.Default().Backend+"\n", out, "missing config falls back to defaults")

	out, _, err = cbRun(t, "config", "set", "backend", "awssm")
	require.NoError(t, err)
	assert.Equal(t, "set backend=aws-sm\n", out, "aliases are persisted canonically")

	out, _, err = cbRun(t, "config", "set", "MODE", "canary")
	require.NoError(t, err)
	assert.Equal(t, "set MODE=canary\n", out)

	out, _, err = cbRun(t, "config", "set", "default_namespace", "team-a")
	require.NoError(t, err)
	assert.Contains(t, out, "set default_namespace=team-a")

	cfg := cbLoadConfig(t, cfgDir)
	assert.Equal(t, "aws-sm", cfg.Backend)
	assert.Equal(t, "canary", cfg.Mode)
	assert.Equal(t, "team-a", cfg.DefaultNamespace)
	cbAssertMode(t, filepath.Join(cfgDir, "config.json"), 0o600)

	out, _, err = cbRun(t, "config", "get", "mode")
	require.NoError(t, err)
	assert.Equal(t, "canary\n", out)

	out, _, err = cbRun(t, "config", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "backend = aws-sm\n")
	assert.Contains(t, out, "mode = canary\n")
	assert.Contains(t, out, "default_namespace = team-a\n")

	out, _, err = cbRun(t, "config", "list", "--json")
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, "aws-sm", decoded["backend"])
}

func TestConfigCmd_CorruptConfigFallsBackToDefaults(t *testing.T) {
	cfgDir := cbIsolate(t)
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte("{broken"), 0o600))

	out, _, err := cbRun(t, "config", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "backend = "+config.Default().Backend)
}

func TestSetField_RejectsUnsupportedKinds(t *testing.T) {
	cfg := config.Default()
	err := setField(&cfg, "version", "2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be set via config set")

	err = setField(&cfg, "telemetry", "on")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type not supported")

	err = setField(&cfg, "nope", "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown config key "nope"`)
}

func TestInitCI_DefaultTargetInCwdAndPrintsSnippet(t *testing.T) {
	cbIsolate(t)
	dir := t.TempDir()
	t.Chdir(dir)

	out, _, err := cbRun(t, "init", "ci")
	require.NoError(t, err)
	target := filepath.Join(dir, "keylatch.yaml")
	assert.Contains(t, out, "Written: "+target)
	assert.Contains(t, out, "GitHub Actions snippet")
	assert.Contains(t, out, "  name: keylatch-ci")
	assert.Contains(t, out, "Get started: keylatch.dev/start")
	cbAssertMode(t, target, 0o600)
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, keylatchYAMLSkeleton, string(data))
	_, statErr := os.Stat(filepath.Join(dir, githubActionsWorkflowPath))
	assert.True(t, os.IsNotExist(statErr))
}

func TestInitCI_WriteForceAndIdempotence(t *testing.T) {
	cbIsolate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(dir, "keylatch.yaml")
	wf := filepath.Join(dir, githubActionsWorkflowPath)

	out, _, err := cbRun(t, "init", "ci", "--write")
	require.NoError(t, err)
	assert.Contains(t, out, "Written: "+wf)
	assert.NotContains(t, out, "GitHub Actions snippet")
	cbAssertMode(t, wf, 0o600)

	require.NoError(t, os.WriteFile(target, []byte("custom: true\n"), 0o600))
	require.NoError(t, os.WriteFile(wf, []byte("custom workflow\n"), 0o600))

	out, _, err = cbRun(t, "init", "ci", "--write")
	require.NoError(t, err)
	assert.Contains(t, out, "keylatch.yaml already exists")
	assert.Contains(t, out, wf+" already exists — skipping")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "custom: true\n", string(data))

	out, _, err = cbRun(t, "init", "ci", "--write", "--force")
	require.NoError(t, err)
	assert.Contains(t, out, "Written: "+target)
	assert.Contains(t, out, "Written: "+wf)
	data, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, keylatchYAMLSkeleton, string(data))
	data, err = os.ReadFile(wf)
	require.NoError(t, err)
	assert.Equal(t, githubActionsSnippet, string(data))
}

func TestBootstrapCmd_DryRunJSONWritesNothing(t *testing.T) {
	cfgDir := cbIsolate(t)
	out, _, err := cbRun(t, "bootstrap", "--dry-run", "--json")
	require.NoError(t, err)
	parsed, err := ParseBootstrapPlan([]byte(out))
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Steps)
	for _, s := range parsed.Steps {
		assert.False(t, s.Done, "dry-run step %s must not be done", s.Path)
	}
	_, statErr := os.Stat(cfgDir)
	assert.True(t, os.IsNotExist(statErr))
}

func TestBootstrapCmd_ForceRequiresConfirmation(t *testing.T) {
	cfgDir := cbIsolate(t)
	out, _, err := cbRun(t, "bootstrap")
	require.NoError(t, err)
	assert.NotEmpty(t, out)
	krPath := filepath.Join(cfgDir, "keyring", "keyring.json")
	original, err := os.ReadFile(krPath)
	require.NoError(t, err)

	out, _, err = cbRunIn(t, "n\n", "bootstrap", "--force")
	require.NoError(t, err)
	assert.Contains(t, out, "Destroy existing keyring and re-initialize? [y/N]: ")
	assert.Contains(t, out, "Aborted.")
	kept, err := os.ReadFile(krPath)
	require.NoError(t, err)
	assert.Equal(t, original, kept)

	out, _, err = cbRunIn(t, "YES\n", "bootstrap", "--force")
	require.NoError(t, err)
	assert.NotContains(t, out, "Aborted.")
	recreated, err := os.ReadFile(krPath)
	require.NoError(t, err)
	assert.NotEqual(t, original, recreated, "confirmed --force re-creates the keyring")
	cbAssertMode(t, krPath, 0o600)
}

func TestInitIntegration_ScaffoldsPerLanguage(t *testing.T) {
	cases := []struct {
		marker string
		agent  string
		script string
		mode   os.FileMode
		runCmd string
	}{
		{"", "Claude-Code", "keylatch-setup.sh", 0o755, "bash scripts/keylatch-setup.sh"},
		{"requirements.txt", "gemini", "keylatch_setup.py", 0o755, "python3 scripts/keylatch_setup.py"},
		{"package.json", "cursor", "keylatchSetup.ts", 0o644, "npx tsx scripts/keylatchSetup.ts"},
	}
	for _, tc := range cases {
		t.Run(tc.script, func(t *testing.T) {
			cbIsolate(t)
			dir := t.TempDir()
			t.Chdir(dir)
			if tc.marker != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, tc.marker), nil, 0o600))
			}
			agent := strings.ToLower(tc.agent)

			out, _, err := cbRun(t, "init", "integration", "--agent", tc.agent)
			require.NoError(t, err)
			assert.Contains(t, out, "Written: .keylatch/integration.yml")
			assert.Contains(t, out, "Written: scripts/"+tc.script)
			assert.Contains(t, out, "Run: "+tc.runCmd)
			assert.Contains(t, out, "agents/"+agent+".md")

			yml, err := os.ReadFile(filepath.Join(dir, ".keylatch", "integration.yml"))
			require.NoError(t, err)
			assert.Contains(t, string(yml), "agent: "+agent)
			cbAssertMode(t, filepath.Join(dir, "scripts", tc.script), tc.mode)

			out, _, err = cbRun(t, "init", "integration", "--agent", tc.agent)
			require.NoError(t, err)
			assert.Contains(t, out, "integration.yml already exists — skipping")
			assert.Contains(t, out, "scripts/"+tc.script+" already exists — skipping")
		})
	}
}

func TestInitIntegration_RejectsMissingOrUnknownAgent(t *testing.T) {
	cbIsolate(t)
	dir := t.TempDir()
	t.Chdir(dir)

	_, _, err := cbRun(t, "init", "integration")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--agent is required")

	_, _, err = cbRun(t, "init", "integration", "--agent", "clippy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown agent "clippy"`)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "refused scaffolds must not write anything")
}

func TestWriteIntegrationFiles_MkdirFailures(t *testing.T) {
	c, _, _ := cbBareCmd()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".keylatch"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scripts"), nil, 0o600))

	err := writeIntegrationConfig(c, dir, "generic", langShell)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")

	err = writeIntegrationScript(c, dir, "generic", langShell)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")
}
