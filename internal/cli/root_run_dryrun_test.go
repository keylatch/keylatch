package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caInitRegistry loads the real template catalog and restores it after the
// test, so templates registered by the test do not leak.
func caInitRegistry(t *testing.T) {
	t.Helper()
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv))
	t.Cleanup(func() { _ = registry.InitFromConfig(context.Background(), os.Getenv) })
}

func caRegister(t *testing.T, provider, category string, preferred registry.RuntimeMode, supported ...registry.RuntimeMode) {
	t.Helper()
	require.NoError(t, registry.Register(registry.ConnectionTemplate{
		Provider:    provider,
		DisplayName: provider,
		Category:    category,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: preferred,
			Supported: supported,
		},
	}))
}

func caDryRunJSON(t *testing.T, args ...string) dryRunWrapper {
	t.Helper()
	out, errOut, err := caRun(t, nil, append([]string{"run", "--dry-run", "--json"}, args...)...)
	require.NoError(t, err, errOut)
	var w dryRunWrapper
	require.NoError(t, json.Unmarshal([]byte(out), &w), out)
	return w
}

func TestRunDryRunPerRuntime(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secret := caSecret("dryrun")
	require.NoError(t, newDispatchedStore(f.cfg, f.env).Set(context.Background(),
		"default/ai/openrouter/api_key", []byte(secret), backend.Meta{}))
	t.Setenv("KEYLATCH_GATEWAY_ADDR", "127.0.0.1:9911")

	tests := []struct {
		runtime string
		want    []string
	}{
		{"gateway_typed", []string{"KEYLATCH_GATEWAY_URL=<resolved: http://127.0.0.1:9911>", "KEYLATCH_GATEWAY_TOKEN=<would-be-issued scope:openrouter.*, ttl:1h>", "KEYLATCH_RUNTIME=gateway_typed"}},
		{"gateway_sdk", []string{"KEYLATCH_RUNTIME=gateway_sdk"}},
		{"direct_brokered", []string{"=<would-be-brokered ephemeral token>", "KEYLATCH_RUNTIME=direct_brokered"}},
		{"gateway_proxy", []string{"KEYLATCH_GATEWAY_TOKEN=<would-be-issued scope:openrouter.*, ttl:1h>", "KEYLATCH_RUNTIME=gateway_proxy"}},
	}
	for _, tc := range tests {
		t.Run(tc.runtime, func(t *testing.T) {
			w := caDryRunJSON(t, "openrouter", "--runtime", tc.runtime, "--", "curl", "-s", "https://example.invalid")
			assert.True(t, w.OK)
			assert.Nil(t, w.Error)
			assert.Equal(t, "v1", w.Plan.Schema)
			assert.Equal(t, tc.runtime, w.Plan.Runtime)
			assert.Equal(t, "openrouter", w.Plan.Connection)
			assert.Equal(t, []string{"curl", "-s", "https://example.invalid"}, w.Plan.Argv)
			joined := strings.Join(w.Plan.EnvAdded, "\n")
			for _, s := range tc.want {
				assert.Contains(t, joined, s)
			}
			assert.Contains(t, w.Plan.EnvStripped, "KEYLATCH_VAULT_PATH")
			assert.False(t, w.Plan.Policy.LLMSession)
			assert.False(t, w.Plan.Policy.ApprovalRequired)
			assert.NotContains(t, joined, secret)
		})
	}

	w := caDryRunJSON(t, "openrouter", "--runtime", "direct_classic_sandboxed", "--approval-jwt", "x.y.z", "--", "env")
	assert.Empty(t, w.Plan.EnvAdded)
	assert.True(t, w.Plan.Policy.ApprovalRequired)
}

func TestRunDryRunHumanReadable(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caSetLLMSession(t)

	out, _, err := caRun(t, nil, "run", "openrouter", "--dry-run", "--", "echo", "hi")
	require.NoError(t, err)
	for _, want := range []string{
		"[dry-run] runtime:    gateway_typed",
		"[dry-run] provider:   openrouter",
		"[dry-run] connection: openrouter",
		"[dry-run] env_added:",
		"[dry-run]   KEYLATCH_GATEWAY_URL=<resolved: http://127.0.0.1:7878>",
		"[dry-run] env_stripped: ",
		"[dry-run] argv:       echo hi",
		"[dry-run] policy:     llm_session=true approval_required=false",
		"[dry-run] no command executed",
	} {
		assert.Contains(t, out, want)
	}
}

func TestRunDryRunCanaryOperatingMode(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	canaryVar := canary.EnvVarName("openrouter") + "=<would-be-canary-token>"

	w := caDryRunJSON(t, "openrouter", "--mode", "canary", "--", "true")
	assert.Contains(t, w.Plan.EnvAdded, canaryVar)

	w = caDryRunJSON(t, "openrouter", "--", "true")
	assert.NotContains(t, w.Plan.EnvAdded, canaryVar)

	cfg := config.Default()
	cfg.Mode = "custom"
	cfg.Custom = &config.CustomModeConfig{CanaryInjectionEnabled: true}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.configDir, "config.json"), data, 0o600))
	w = caDryRunJSON(t, "openrouter", "--", "true")
	assert.Contains(t, w.Plan.EnvAdded, canaryVar)
}

func TestRunDryRunDirectCallEmptyEnvStripped(t *testing.T) {
	caNewEnv(t)
	caInitRegistry(t)
	c := &cobra.Command{}
	var out bytes.Buffer
	c.SetOut(&out)
	runDryRun(c, "openrouter", []string{"ls"}, runtime.RuntimeDirectClassicSandboxed, "", "", false)
	assert.NotContains(t, out.String(), "[dry-run] env_added:")
	assert.Contains(t, out.String(), "[dry-run] argv:       ls")
}

func TestPrintAllowlistError(t *testing.T) {
	c := &cobra.Command{}
	var errOut bytes.Buffer
	c.SetErr(&errOut)
	printAllowlistError(c, "github", []string{"bash", "-c", "id"}, []string{"gh", "git"})
	s := errOut.String()
	assert.Contains(t, s, `Error: "bash" is not in the allowlist for the github connection.`)
	assert.Contains(t, s, "Allowed: gh, git")
	assert.Contains(t, s, "keylatch run github --allow bash -- bash -c id")
	assert.Contains(t, s, "exfiltrate the credential")

	errOut.Reset()
	printAllowlistError(c, "github", nil, nil)
	assert.Contains(t, errOut.String(), `Error: "" is not in the allowlist`)
	assert.NotContains(t, errOut.String(), "Allowed:")
}

func TestParseRunArgs(t *testing.T) {
	tests := []struct {
		args    []string
		conn    string
		cmd     []string
		wantErr string
	}{
		{nil, "", nil, ""},
		{[]string{"github", "--", "gh", "pr"}, "github", []string{"gh", "pr"}, ""},
		{[]string{"--", "ls"}, "", []string{"ls"}, ""},
		{[]string{"github", "extra", "--", "gh"}, "", nil, "unexpected arguments before '--': [extra]"},
		{[]string{"github", "gh", "api"}, "github", []string{"gh", "api"}, ""},
	}
	for _, tc := range tests {
		conn, cmd, err := parseRunArgs(tc.args)
		if tc.wantErr != "" {
			assert.EqualError(t, err, tc.wantErr)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tc.conn, conn)
		assert.Equal(t, tc.cmd, cmd)
	}
}

func TestLoadConnectionBackend(t *testing.T) {
	caNewEnv(t)
	caInitRegistry(t)
	ctx := context.Background()

	_, _, _, err := loadConnectionBackend(ctx, "no-such-provider")
	assert.ErrorIs(t, err, registry.ErrProviderNotFound)

	_, _, _, err = loadConnectionBackend(ctx, "openrouter")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend:")
	assert.ErrorIs(t, err, backend.ErrBootstrapRequired)

	caNewVault(t, envelope.XChaCha20Poly1305)
	caRegister(t, "ca-nocat", "", registry.RuntimeGatewayTyped, registry.RuntimeGatewayTyped)
	b, tmpl, storagePath, err := loadConnectionBackend(ctx, "ca-nocat")
	require.NoError(t, err)
	assert.Equal(t, "ca-nocat", tmpl.Provider)
	assert.Equal(t, "default/ai/ca-nocat/meta", storagePath)
	assert.Equal(t, "file", b.Name())

	b, _, storagePath, err = loadConnectionBackend(ctx, "openrouter")
	require.NoError(t, err)
	assert.Equal(t, "default/ai/openrouter/meta", storagePath)
	require.NoError(t, closeAndZeroBackend(b))
}

func TestUsableReasonPerSession(t *testing.T) {
	caNewEnv(t)
	caInitRegistry(t)
	caRegister(t, "ca-sandboxed", "ai", "", "direct_classic_sandboxed")
	caRegister(t, "ca-unsupported", "ai", "")
	caRegister(t, "ca-proxy", "ai", registry.RuntimeGatewayProxy, "direct_classic_sandboxed", registry.RuntimeGatewayProxy)

	tests := []struct {
		provider   string
		isLLM      bool
		usable     string
		wantReason string
	}{
		{"ca-sandboxed", false, "yes", ""},
		{"ca-sandboxed", true, "no", "llm-session"},
		{"ca-unsupported", false, "no", "no-gateway"},
		{"ca-unsupported", true, "no", "llm-session"},
		{"ca-proxy", true, "yes", ""},
		{"ca-missing", false, "no", "unknown-provider"},
	}
	for _, tc := range tests {
		u, r := usableReason(connections.Connection{Provider: tc.provider}, tc.isLLM)
		assert.Equal(t, tc.usable, u, tc.provider)
		assert.Equal(t, tc.wantReason, r, tc.provider)
	}
}

func TestRuntimeDoctorReport(t *testing.T) {
	f := caNewEnv(t)
	caInitRegistry(t)
	caRegister(t, "ca-all", "ai", registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped, registry.RuntimeGatewaySDK, registry.RuntimeDirectBrokered,
		registry.RuntimeGatewayProxy, "direct_classic_sandboxed")
	caRegister(t, "ca-brokered", "ai", registry.RuntimeDirectBrokered, registry.RuntimeDirectBrokered, "direct_classic_sandboxed")
	caRegister(t, "ca-sandbox-pref", "ai", "direct_classic_sandboxed", "direct_classic_sandboxed")

	byMode := func(r runtimeDoctorReport) map[string]runtimeModeStatus {
		m := map[string]runtimeModeStatus{}
		for _, s := range r.Modes {
			m[s.Mode] = s
		}
		return m
	}
	sbAvail, sbReason, _ := sandboxModeAvailability()

	r := byMode(buildRuntimeDoctorReport(os.Getenv, "ca-all"))
	assert.False(t, r["gateway_typed"].Available)
	assert.Equal(t, "gateway not running: run 'keylatch gateway up'", r["gateway_typed"].Reason)
	assert.True(t, r["direct_brokered"].Available)
	assert.Equal(t, "supported", r["direct_brokered"].Reason)
	assert.Equal(t, sbAvail, r["direct_classic_sandboxed"].Available)
	assert.Contains(t, r["direct_classic_sandboxed"].Reason, sbReason)

	gwDir := filepath.Join(f.root, "gateway")
	require.NoError(t, os.MkdirAll(gwDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(gwDir, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600))
	r = byMode(buildRuntimeDoctorReport(os.Getenv, "ca-all"))
	assert.True(t, r["gateway_typed"].Available)
	assert.Equal(t, "gateway running (preferred mode)", r["gateway_typed"].Reason)
	assert.Equal(t, "gateway running", r["gateway_sdk"].Reason)

	r = byMode(buildRuntimeDoctorReport(os.Getenv, "ca-brokered"))
	assert.Equal(t, "preferred mode — broker strategy available", r["direct_brokered"].Reason)
	assert.Equal(t, "not in ca-brokered runtime_support", r["gateway_typed"].Reason)

	r = byMode(buildRuntimeDoctorReport(os.Getenv, "ca-sandbox-pref"))
	if sbAvail {
		assert.True(t, strings.HasSuffix(r["direct_classic_sandboxed"].Reason, "(preferred mode)"))
	} else {
		assert.Contains(t, r["direct_classic_sandboxed"].Reason, "run 'keylatch sandbox doctor'")
	}

	assert.Empty(t, buildRuntimeDoctorReport(os.Getenv, "").Modes)
	missing := buildRuntimeDoctorReport(os.Getenv, "ca-nope")
	require.Len(t, missing.Modes, 1)
	assert.Contains(t, missing.Modes[0].Reason, "provider not found")
}

func TestRuntimeDoctorCmdOutput(t *testing.T) {
	caNewEnv(t)
	caInitRegistry(t)
	caRegister(t, "ca-gw", "ai", registry.RuntimeGatewayTyped, registry.RuntimeGatewayTyped)

	run := func(args ...string) string {
		c := newRuntimeDoctorCmd()
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetArgs(args)
		require.NoError(t, c.Execute())
		return out.String()
	}
	out := run("ca-gw")
	assert.Contains(t, out, "runtime doctor — provider: ca-gw")
	assert.Contains(t, out, "  [FAIL] gateway_typed: gateway not running")
	assert.Contains(t, out, "  [FAIL] gateway_sdk: not in ca-gw runtime_support")

	var rep runtimeDoctorReport
	require.NoError(t, json.Unmarshal([]byte(run("ca-gw", "--json")), &rep))
	assert.Equal(t, "ca-gw", rep.Provider)
	assert.Len(t, rep.Modes, 5)

	caRegister(t, "ca-ok", "ai", registry.RuntimeDirectBrokered, registry.RuntimeDirectBrokered)
	assert.Contains(t, run("ca-ok"), "  [ok  ] direct_brokered: preferred mode")
}

func TestIsDoctorHintSuppressed(t *testing.T) {
	root := NewRootCommand()
	find := func(name string) *cobra.Command {
		c, _, err := root.Find([]string{name})
		require.NoError(t, err)
		return c
	}
	assert.True(t, IsDoctorHintSuppressed(find("doctor")))
	assert.True(t, IsDoctorHintSuppressed(find("completion")))

	set := find("set")
	assert.False(t, IsDoctorHintSuppressed(set))
	set.InitDefaultHelpFlag()
	require.NoError(t, set.Flags().Set("help", "true"))
	assert.True(t, IsDoctorHintSuppressed(set))

	list := find("list")
	require.NoError(t, root.Flags().Set("version", "true"))
	assert.True(t, IsDoctorHintSuppressed(list))
}

func TestRootLogLevelFlag(t *testing.T) {
	caNewEnv(t)
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	ctx := context.Background()

	for _, tc := range []struct {
		level   string
		enabled slog.Level
		below   slog.Level
	}{
		{"debug", slog.LevelDebug, slog.LevelDebug - 1},
		{"WARN", slog.LevelWarn, slog.LevelInfo},
		{"error", slog.LevelError, slog.LevelWarn},
		{"bogus", slog.LevelInfo, slog.LevelDebug},
	} {
		out, _, err := caRun(t, nil, "--log-level", tc.level, "get-masked", "svc", "key")
		require.NoError(t, err)
		assert.Equal(t, "svc.key = ****\n", out)
		assert.True(t, slog.Default().Enabled(ctx, tc.enabled), tc.level)
		assert.False(t, slog.Default().Enabled(ctx, tc.below), tc.level)
	}
}

func TestConnectionsCmdDelegatesToList(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	for _, args := range [][]string{{"connections"}, {"connections", "list"}} {
		out, _, err := caRun(t, nil, args...)
		require.NoError(t, err, args)
		assert.Contains(t, out, "No connections yet — run `keylatch connect <provider>`", args)
	}
}

func TestUnwiredStubCommandsShape(t *testing.T) {
	call := newCallCmdStub()
	assert.Equal(t, "call <connection> <endpoint>", call.Use)
	assert.Equal(t, string(runtime.RuntimeGatewayTyped), call.Flag("runtime").DefValue)
	assert.NotNil(t, call.Flag("approval-jwt"))
	assert.Equal(t, "describe <service>", newDescribeCmdStub().Use)
	assert.Equal(t, "validate <service>", newValidateCmdStub().Use)
	assert.NotNil(t, notImplementedRunE(1))
}

func TestRunHelpersAndAdapters(t *testing.T) {
	c := &cobra.Command{}
	in := strings.NewReader("in")
	var out, errOut bytes.Buffer
	c.SetIn(in)
	c.SetOut(&out)
	c.SetErr(&errOut)
	h := handlerArgsFromCmd(c, []string{"a", "b"})
	assert.Equal(t, []string{"a", "b"}, h.Positional)
	assert.Empty(t, h.Flags)
	assert.Equal(t, &out, h.Stdout)
	assert.Equal(t, &errOut, h.Stderr)
	assert.NotNil(t, h.Env)

	dir := t.TempDir()
	pid := filepath.Join(dir, "gw.pid")
	a := &gatewayServerAdapter{addr: "127.0.0.1:1", pidPath: pid}
	assert.Equal(t, "127.0.0.1:1", a.Addr())
	assert.False(t, a.Running())
	require.NoError(t, os.WriteFile(pid, []byte(strconv.Itoa(os.Getpid())), 0o600))
	assert.True(t, a.Running())

	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	addr, err := proxyRunAddr(env(map[string]string{"KEYLATCH_PROXY_ADDR": "127.0.0.1:9000"}))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:9000", addr)
	_, err = proxyRunAddr(env(map[string]string{"KEYLATCH_PROXY_ADDR": "nonsense"}))
	assert.ErrorContains(t, err, "KEYLATCH_PROXY_ADDR")
	_, err = gatewayRunAddr(env(map[string]string{"KEYLATCH_GATEWAY_ADDR": "nonsense"}))
	assert.ErrorContains(t, err, "KEYLATCH_GATEWAY_ADDR")

	assert.Nil(t, mapCustomConfig(nil))
	got := mapCustomConfig(&config.CustomModeConfig{TelemetryEnabled: true, ExperimentalGated: true})
	assert.Equal(t, &runtime.CustomModeConfig{TelemetryEnabled: true, ExperimentalGated: true}, got)

	assert.NotNil(t, newCLIBroker(context.Background()))
}
