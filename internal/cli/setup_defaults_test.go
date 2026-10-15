package cli_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy"
)

type headlessResult struct {
	OK      bool   `json:"ok"`
	Backend string `json:"backend"`
	Policy  string `json:"policy"`
	Doctor  *struct {
		OK   bool `json:"ok"`
		Fail int  `json:"fail"`
		Warn int  `json:"warn"`
	} `json:"doctor"`
	Error string `json:"error"`
}

// headlessSetup runs `keylatch setup --headless` against a throwaway home.
func headlessSetup(t *testing.T, args ...string) (string, headlessResult) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	configDir := filepath.Join(home, ".keylatch")
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	t.Setenv("KEYLATCH_DATA_DIR", filepath.Join(configDir, "vault"))
	t.Setenv("KEYLATCH_BACKEND", "")

	var stdout, stderr bytes.Buffer
	root := cli.NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"setup", "--headless"}, args...))
	require.NoError(t, root.Execute(), stderr.String())

	var res headlessResult
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &res), stderr.String())
	return configDir, res
}

func TestSetupWritesDefaultDenyPolicy(t *testing.T) {
	configDir, res := headlessSetup(t, "--backend", "file", "--insecure-file-kek")
	require.True(t, res.OK, res.Error)
	assert.Equal(t, "created", res.Policy)

	p, err := policy.Load(filepath.Join(configDir, "policy.json"))
	require.NoError(t, err)
	assert.True(t, p.DefaultDeny)
	assert.Equal(t, policy.ModeEnforcing, p.Mode)
	assert.Empty(t, p.Rules)

	for _, actor := range []string{"agent", "claude-code", "anyone"} {
		d := p.Check(policy.Request{Actor: actor, Connection: "openai", Capability: "inject", LLMSession: true})
		assert.False(t, d.Allow, "%s must be denied by default", actor)
	}
}

func TestSetupHeadlessBitwarden(t *testing.T) {
	configDir, res := headlessSetup(t, "--backend", "bw",
		"--server", "https://vault.example.com", "--organization-id", "org-123", "--namespace", "work")
	require.True(t, res.OK, res.Error)
	assert.Equal(t, "bw", res.Backend)

	cfg, err := config.Load(filepath.Join(configDir, "config.json"))
	require.NoError(t, err)
	assert.Equal(t, "bw", cfg.Backend)
	assert.Equal(t, "work", cfg.DefaultNamespace)
	require.NotNil(t, cfg.BW)
	assert.Equal(t, "https://vault.example.com", cfg.BW.Server)
	assert.Equal(t, "org-123", cfg.BW.OrganizationID)
}

func TestSetupEndsWithDoctor(t *testing.T) {
	_, res := headlessSetup(t, "--backend", "file", "--insecure-file-kek")
	require.True(t, res.OK, res.Error)
	require.NotNil(t, res.Doctor, "setup must end with the doctor verdict")
	assert.Zero(t, res.Doctor.Fail, "a set-up machine has no failing check")
	assert.True(t, res.Doctor.OK)
}
