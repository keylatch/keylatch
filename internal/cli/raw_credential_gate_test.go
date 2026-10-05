package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/require"
)

// sessionClaimEnv holds every environment value a caller could set to claim
// a verified session: variables an earlier session check trusted, a socket
// path that does not answer, and a ticket nobody signed.
func sessionClaimEnv(t *testing.T) map[string]string {
	return map[string]string{
		"KEYLATCH_ALLOW_UNVERIFIED_SESSION": "1",
		"KEYLATCH_LLM_TICKET":               "anything",
		"KEYLATCH_DAEMON_SOCKET":            filepath.Join(t.TempDir(), "missing.sock"),
		llmcontext.TicketEnv:                "forged.ticket.value",
	}
}

func isolatedGateEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_KEYRING_DIR", "")
	testutil.ClearLLMSessionEnv(t)
	return dir
}

func TestRawCredentialGateIgnoresSessionClaims(t *testing.T) {
	dir := isolatedGateEnv(t)
	for k, v := range sessionClaimEnv(t) {
		t.Setenv(k, v)
	}
	env := llmcontext.DefaultLookup

	gate := func() error {
		return RequireRawCredentialOptIn(true, configAllowsUnverifiedSession(env))
	}

	require.ErrorIs(t, gate(), errRawCredentialExposure, "no config file")

	cfgPath := paths.Config(env)
	require.Equal(t, filepath.Join(dir, "config.json"), cfgPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte("{not json"), 0o600))
	require.ErrorIs(t, gate(), errRawCredentialExposure, "unreadable config")

	cfg := config.Default()
	require.NoError(t, config.Save(cfgPath, cfg))
	require.ErrorIs(t, gate(), errRawCredentialExposure, "config without the opt-in")

	cfg.AllowUnverifiedSession = true
	require.NoError(t, config.Save(cfgPath, cfg))
	require.NoError(t, gate(), "only the operator's config opt-in opens the gate")
}

func TestRawCredentialGateIgnoresValidTicket(t *testing.T) {
	isolatedGateEnv(t)
	raw, err := issueLaunchTicket(llmcontext.DefaultLookup, "claude-code")
	require.NoError(t, err)
	t.Setenv(llmcontext.TicketEnv, raw)

	require.ErrorIs(t,
		RequireRawCredentialOptIn(true, configAllowsUnverifiedSession(llmcontext.DefaultLookup)),
		errRawCredentialExposure, "a signed ticket marks an agent; it never opens a raw-credential path")
}

const rawGateHelperEnv = "KEYLATCH_RAW_GATE_TEST_HELPER"

// TestRawGateHelperProcess runs `keylatch get` for TestGetRefusesWithSessionClaims;
// the command exits the process.
func TestRawGateHelperProcess(t *testing.T) {
	if os.Getenv(rawGateHelperEnv) != "1" {
		t.Skip("helper process for TestGetRefusesWithSessionClaims")
	}
	root := NewRootCommand()
	root.SetArgs([]string{"get", "openrouter", "api_key"})
	_ = root.Execute()
	os.Exit(0)
}

func TestGetRefusesWithSessionClaims(t *testing.T) {
	if os.Getenv(rawGateHelperEnv) == "1" {
		t.Skip("running as the helper")
	}
	isolatedGateEnv(t)
	for k, v := range sessionClaimEnv(t) {
		t.Setenv(k, v)
	}
	t.Setenv(rawGateHelperEnv, "1")

	cmd := exec.Command(os.Args[0], "-test.run=^TestRawGateHelperProcess$")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "get must exit non-zero, got %v; stderr: %s", err, stderr.String())
	require.Equal(t, exitcode.SecurityBlock, exitErr.ExitCode(), "stderr: %s", stderr.String())
	require.Contains(t, stderr.String(), errRawCredentialExposure.Error())
}
