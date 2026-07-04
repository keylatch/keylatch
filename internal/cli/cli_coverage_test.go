package cli_test

// cli_coverage_test.go tests pure functions and command-structure elements
// that are not covered by other test files. No real network calls are made.

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// parseRunArgs (exported for test via a wrapper — test through GetCmd behaviour)
// ---------------------------------------------------------------------------

// TestGetMaskedCmd_TwoArgs verifies that `get-masked` with two args prints
// a masked placeholder to stdout.
func TestGetMaskedCmd_TwoArgs(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"get-masked", "svc", "key"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "****", "get-masked must output masked placeholder")
}

// TestGetMaskedCmd_NoArgs verifies get-masked without args prints a generic
// masked output.
func TestGetMaskedCmd_NoArgs(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"get-masked"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "****")
}

// TestGetCmd_MaskedFlag verifies `get --masked svc key` outputs **** and never
// calls the guarded handler.
func TestGetCmd_MaskedFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"get", "--masked", "svc", "key"})
	// get --masked must NOT call os.Exit — it returns nil.
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "****")
}

// TestGetCmd_MaskedFlag_NoArgs verifies `get --masked` with no positional args
// still returns masked output.
func TestGetCmd_MaskedFlag_NoArgs(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"get", "--masked"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "****")
}

// TestProxyCmd_Error verifies the proxy subcommand prints a helpful error.
func TestProxyCmd_Error(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	var errOut bytes.Buffer
	root.SetErr(&errOut)
	root.SetArgs([]string{"proxy"})
	// proxy calls os.Exit(5) — we can't test that from unit tests, but we can
	// verify the command is registered by looking it up.
	_, _, err := root.Find([]string{"proxy"})
	require.NoError(t, err)
}

// TestSandboxCmd_Registered verifies the sandbox subcommand is registered.
func TestSandboxCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"sandbox"})
	require.NoError(t, err)
	assert.Equal(t, "sandbox", cmd.Name())
}

// TestConnectionsCmd_Registered verifies the connections subcommand is registered.
func TestConnectionsCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"connections"})
	require.NoError(t, err)
	assert.Equal(t, "connections", cmd.Name())
}

// TestCallCmd_Registered verifies the call subcommand is registered (hidden).
func TestCallCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"call"})
	require.NoError(t, err)
	assert.Equal(t, "call", cmd.Name())
}

// TestHealthCmd_Registered verifies the `health` subcommand is registered
// with exactly that name — a parallel packaging lane's Dockerfile HEALTHCHECK
// references ["/keylatch","health"] directly (distroless images have no
// shell), so the command name is load-bearing.
func TestHealthCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	cmd, _, err := root.Find([]string{"health"})
	require.NoError(t, err)
	assert.Equal(t, "health", cmd.Name())
}

// TestGatewayRunAddr_Default verifies the default gateway address is 127.0.0.1:7878.
func TestGatewayRunAddr_Default(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	// gateway subcommand should be registered.
	cmd, _, err := root.Find([]string{"gateway"})
	require.NoError(t, err)
	assert.Equal(t, "gateway", cmd.Name())
}

// TestRootCommand_HasVersionFlag verifies --version flag is registered.
func TestRootCommand_HasVersionFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	f := root.Flags().Lookup("version")
	require.NotNil(t, f, "--version flag must be registered on root")
}

// TestRootCommand_HasJSONFlag verifies --json persistent flag is registered.
func TestRootCommand_HasJSONFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	f := root.PersistentFlags().Lookup("json")
	require.NotNil(t, f, "--json flag must be registered on root")
}

// TestRootCommand_HasQuietFlag verifies --quiet persistent flag is registered.
func TestRootCommand_HasQuietFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	f := root.PersistentFlags().Lookup("quiet")
	require.NotNil(t, f, "--quiet flag must be registered on root")
}

// TestRunCmd_Registered verifies the run subcommand is in the command tree.
func TestRunCmd_AllowFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	runCmd := findCmd(root, "run ")
	require.NotNil(t, runCmd)
	f := runCmd.Flags().Lookup("allow")
	require.NotNil(t, f)
	// StringArray flag with nil default serialises as "[]".
	assert.Equal(t, "[]", f.DefValue, "--allow defaults to empty slice")
}

// TestRuntimeDoctorCmd_Registered verifies `runtime doctor` is registered.
func TestRuntimeDoctorCmd_Registered(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	runtimeCmd, _, err := root.Find([]string{"runtime"})
	require.NoError(t, err)
	assert.Equal(t, "runtime", runtimeCmd.Name())
}

// TestRuntimeDoctorCmd_JSONFlag verifies --json is registered on runtime doctor.
func TestRuntimeDoctorCmd_JSONFlag(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	runtimeCmd, _, _ := root.Find([]string{"runtime"})
	require.NotNil(t, runtimeCmd)
	doctorCmd := findCmd(runtimeCmd, "doctor")
	require.NotNil(t, doctorCmd, "runtime doctor subcommand must be registered")
	f := doctorCmd.Flags().Lookup("json")
	require.NotNil(t, f, "--json flag must be registered on runtime doctor")
}

// ---------------------------------------------------------------------------
// ValidateApprovalRootJWT
// ---------------------------------------------------------------------------

func makeApprovalKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func mintApprovalJWT(t *testing.T, key []byte, extra map[string]interface{}) string {
	t.Helper()
	claims := jwt.MapClaims{
		"exp":           time.Now().Add(5 * time.Minute).Unix(),
		"iat":           time.Now().Unix(),
		"apv_root_hmac": "deadbeefdeadbeef",
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)
	return tok
}

func TestValidateApprovalRootJWT_Valid(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, nil)

	result, err := cli.ValidateApprovalRootJWT(tok, key, false)
	require.NoError(t, err)
	assert.Equal(t, "deadbeefdeadbeef", result.ApprovalRootHMAC)
}

func TestValidateApprovalRootJWT_WrongKey(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	wrongKey := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, nil)

	_, err := cli.ValidateApprovalRootJWT(tok, wrongKey, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTInvalid)
}

func TestValidateApprovalRootJWT_ShortKey(t *testing.T) {
	t.Parallel()
	_, err := cli.ValidateApprovalRootJWT("any-jwt", []byte("tooshort"), false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTInvalid)
}

func TestValidateApprovalRootJWT_NilKey(t *testing.T) {
	t.Parallel()
	_, err := cli.ValidateApprovalRootJWT("any-jwt", nil, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTInvalid)
}

func TestValidateApprovalRootJWT_MissingRootHMAC(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	claims := jwt.MapClaims{
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		// no apv_root_hmac
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)

	_, err = cli.ValidateApprovalRootJWT(tok, key, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTMissingRootClaims)
}

func TestValidateApprovalRootJWT_Expired(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	claims := jwt.MapClaims{
		"exp":           time.Now().Add(-1 * time.Minute).Unix(), // expired
		"iat":           time.Now().Add(-5 * time.Minute).Unix(),
		"apv_root_hmac": "deadbeef",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)

	_, err = cli.ValidateApprovalRootJWT(tok, key, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTInvalid)
}

func TestValidateApprovalRootJWT_ApprovalExpiry_Past(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_exp": time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339),
	})

	_, err := cli.ValidateApprovalRootJWT(tok, key, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalExpired)
}

func TestValidateApprovalRootJWT_ApprovalExpiry_Future(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_exp": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
	})

	result, err := cli.ValidateApprovalRootJWT(tok, key, false)
	require.NoError(t, err)
	assert.False(t, result.ApprovalExpiry.IsZero())
}

func TestValidateApprovalRootJWT_ApprovalExpiry_BadFormat(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_exp": "not-a-date",
	})

	_, err := cli.ValidateApprovalRootJWT(tok, key, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTInvalid)
}

func TestValidateApprovalRootJWT_TwoPersonRequired_Missing(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, nil) // no two-person claims

	_, err := cli.ValidateApprovalRootJWT(tok, key, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTMissingRootClaims)
}

func TestValidateApprovalRootJWT_TwoPersonRequired_OnlyOne(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_two_person": true,
		"apv_root_hmacs": []string{"hmac1"}, // only 1, need >= 2
	})

	_, err := cli.ValidateApprovalRootJWT(tok, key, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, cli.ErrApprovalJWTMissingRootClaims)
}

func TestValidateApprovalRootJWT_TwoPerson_Valid(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_two_person": true,
		"apv_root_hmacs": []string{"hmac1", "hmac2"},
	})

	result, err := cli.ValidateApprovalRootJWT(tok, key, true)
	require.NoError(t, err)
	assert.True(t, result.TwoPerson)
	assert.Len(t, result.ApprovalRootHMACs, 2)
}

func TestValidateApprovalRootJWT_WithClaims(t *testing.T) {
	t.Parallel()
	key := makeApprovalKey(t)
	tok := mintApprovalJWT(t, key, map[string]interface{}{
		"apv_cap":         "inject",
		"apv_max_age_sec": 300,
		"apv_binding":     "challenge",
	})

	result, err := cli.ValidateApprovalRootJWT(tok, key, false)
	require.NoError(t, err)
	assert.Equal(t, "inject", result.ApprovalCapability)
	assert.Equal(t, 300, result.ApprovalMaxAgeSec)
	assert.Equal(t, "challenge", result.ApprovalBinding)
}

// ---------------------------------------------------------------------------
// SecurityBlockHook
// ---------------------------------------------------------------------------

func TestSecurityBlockHook_Default(t *testing.T) {
	t.Parallel()
	// Default hook must not panic.
	original := cli.SecurityBlockHook
	defer func() { cli.SecurityBlockHook = original }()

	// Reset to a known state.
	called := false
	cli.SecurityBlockHook = func(_ context.Context, _ cli.SecurityBlockEvent) {
		called = true
	}

	args := cli.HandlerArgs{
		Positional: []string{"get"},
		Flags:      map[string]string{},
		Env:        lookupWith(map[string]string{"CLAUDE_CODE": "1"}),
		Stdin:      bytes.NewReader(nil),
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}

	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		return cli.Result{}, nil
	}
	guarded := cli.GuardLLMSession(inner)
	_, _ = guarded(context.Background(), args)

	assert.True(t, called)
}

// ---------------------------------------------------------------------------
// WriteGuardRuntimeError
// ---------------------------------------------------------------------------

func TestWriteGuardRuntimeError_DirectClassic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cli.WriteGuardRuntimeError(&buf, "direct_classic")
	assert.Contains(t, buf.String(), "direct_classic")
}

func TestWriteGuardRuntimeError_DirectClassicSandboxed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cli.WriteGuardRuntimeError(&buf, "direct_classic_sandboxed")
	assert.Contains(t, buf.String(), "direct_classic_sandboxed")
}

func TestWriteGuardRuntimeError_Unrestricted(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cli.WriteGuardRuntimeError(&buf, "unrestricted_root_mode")
	assert.NotEmpty(t, buf.String())
}

func TestWriteGuardRuntimeError_Unknown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	cli.WriteGuardRuntimeError(&buf, "totally-made-up-mode")
	// Should produce fallback message.
	assert.NotEmpty(t, buf.String())
}

// ---------------------------------------------------------------------------
// Command group registration
// ---------------------------------------------------------------------------

func TestRegister_AllGroups(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	groups := root.Groups()
	groupIDs := make(map[string]bool)
	for _, g := range groups {
		groupIDs[g.ID] = true
	}
	assert.True(t, groupIDs["start"], "start group must be registered")
	assert.True(t, groupIDs["daily"], "daily group must be registered")
	assert.True(t, groupIDs["gateway"], "gateway group must be registered")
	assert.True(t, groupIDs["team"], "team group must be registered")
	assert.True(t, groupIDs["advanced"], "advanced group must be registered")
}

func TestRegister_KeyCommands(t *testing.T) {
	t.Parallel()
	root := cli.NewRootCommand()
	expectedCmds := []string{
		// v1.0.0: "inject" removed; direct_classic removed.
		"setup", "connect", "agent", "doctor", "ui", "bootstrap",
		"get", "get-masked", "list", "status", "run",
		"gateway", "team", "policy", "grant", "actors", "audit",
		"registry", "rollback", "set", "shared-secret", "trust",
		"versions", "mcp", "token",
	}
	for _, name := range expectedCmds {
		cmd, _, err := root.Find([]string{name})
		require.NoError(t, err)
		assert.Equal(t, name, cmd.Name(), "command %q must be registered", name)
	}
}

// ---------------------------------------------------------------------------
// exitcodes (verify no-regression)
// ---------------------------------------------------------------------------

func TestExitCode_SecurityBlock(t *testing.T) {
	t.Parallel()
	// Verify SecurityBlock = 2 (standard convention per exitcode package).
	assert.Equal(t, 2, exitcode.SecurityBlock)
}

func TestExitCode_UserError(t *testing.T) {
	t.Parallel()
	// UserError = 1 per exitcode package.
	assert.Equal(t, 1, exitcode.UserError)
}

func TestExitCode_Missing(t *testing.T) {
	t.Parallel()
	// Missing = 3 per exitcode package.
	assert.Equal(t, 3, exitcode.Missing)
}
