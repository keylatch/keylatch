package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cbLoadConfig(t *testing.T, cfgDir string) config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(cfgDir, "config.json"))
	require.NoError(t, err)
	return cfg
}

func TestSetupHeadless_BootstrapsFileBackendWithPrivatePerms(t *testing.T) {
	cfgDir := cbIsolate(t)

	out, stderr, err := cbRun(t, "setup", "--headless")
	require.NoError(t, err)
	assert.Empty(t, out, "headless mode keeps stdout quiet")
	var res setupHeadlessResult
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(lastLine(stderr))), &res))
	assert.Equal(t, setupHeadlessResult{OK: true, Backend: "file"}, res)

	assert.Equal(t, "file", cbLoadConfig(t, cfgDir).Backend)
	cbAssertMode(t, cfgDir, 0o700)
	cbAssertMode(t, filepath.Join(cfgDir, "vault"), 0o700)
	cbAssertMode(t, filepath.Join(cfgDir, "config.json"), 0o600)
	cbAssertMode(t, filepath.Join(cfgDir, "keyring", "identity"), 0o600)
	cbAssertMode(t, filepath.Join(cfgDir, "keyring", "keyring.json"), 0o600)
	keyringPath := filepath.Join(cfgDir, "keyring", "keyring.json")

	before, err := os.ReadFile(keyringPath)
	require.NoError(t, err)
	identity, err := os.ReadFile(filepath.Join(cfgDir, "keyring", "identity"))
	require.NoError(t, err)

	_, stderr, err = cbRun(t, "setup", "--headless", "--backend", "file")
	require.NoError(t, err)
	assert.Contains(t, stderr, `{"ok":true,"backend":"file"}`)
	after, err := os.ReadFile(keyringPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "keyring must not be regenerated")
	identityAfter, err := os.ReadFile(filepath.Join(cfgDir, "keyring", "identity"))
	require.NoError(t, err)
	assert.Equal(t, identity, identityAfter, "KEK identity must not be regenerated")
}

func TestSetupHeadless_CanonicalizesBackendAlias(t *testing.T) {
	cfgDir := cbIsolate(t)
	_, stderr, err := cbRun(t, "setup", "--headless", "--backend", "hashivault")
	require.NoError(t, err)
	assert.Contains(t, stderr, `{"ok":true,"backend":"vault"}`)
	assert.Equal(t, "vault", cbLoadConfig(t, cfgDir).Backend)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func TestSetupNonInteractive_FreshInstall(t *testing.T) {
	cfgDir := cbIsolate(t)
	_, _, err := cbRun(t, "setup", "--non-interactive", "--backend", "file", "--stdin-field", "api_key=placeholder")
	require.NoError(t, err)
	assert.Equal(t, "file", cbLoadConfig(t, cfgDir).Backend)
	cbAssertMode(t, filepath.Join(cfgDir, "keyring", "keyring.json"), 0o600)

	_, stderr, err := cbRun(t, "setup", "--non-interactive", "--backend", "file")
	require.NoError(t, err)
	assert.Contains(t, stderr, `{"ok":true,"note":"already configured"}`)
}

func TestSetupFromEnv_UsesKeylatchBackend(t *testing.T) {
	cfgDir := cbIsolate(t)
	t.Setenv("KEYLATCH_BACKEND", "op")
	_, _, err := cbRun(t, "setup", "--from-env")
	require.NoError(t, err)
	assert.Equal(t, "op", cbLoadConfig(t, cfgDir).Backend)
}

func TestSetupInteractive_BasicMenuChoices(t *testing.T) {
	cases := []struct {
		choice string
		want   string
	}{
		{"1", "file"},
		{"7", "file"},
		{"", "file"},
	}
	if runtime.GOOS != "darwin" {
		cases = append(cases, struct {
			choice string
			want   string
		}{"2", "file"})
	}
	for _, tc := range cases {
		t.Run("choice_"+tc.choice, func(t *testing.T) {
			cfgDir := cbIsolate(t)
			// storage, decline recommended, menu choice, mode, provider, open UI
			cbScriptStdin(t, strings.Join([]string{"local", "n", tc.choice, "", "", ""}, "\n")+"\n")
			out, stderr, err := cbRun(t, "setup", "--no-daemon-start")
			require.NoError(t, err)
			assert.Contains(t, out, "Welcome to Keylatch.")
			assert.Contains(t, out, "Choose a backend:")
			assert.Contains(t, out, "Backend \""+tc.want+"\" configured.")
			assert.Contains(t, out, "Operating mode: standard")
			assert.Contains(t, out, "Skipping — run `keylatch connect <provider>` when ready.")
			assert.Contains(t, out, "You're set up!")
			assert.NotContains(t, out, "[3/5]")
			if tc.choice == "2" {
				assert.Contains(t, stderr, "macOS Keychain is only available on macOS")
			}
			if tc.choice == "7" {
				assert.Contains(t, out, "Invalid choice")
			}
			assert.Equal(t, tc.want, cbLoadConfig(t, cfgDir).Backend)
		})
	}
}

func TestSetupInteractive_StorageBranchReprompts(t *testing.T) {
	cbIsolate(t)
	cbScriptStdin(t, "maybe\nl\n\n\n\n\n")
	out, _, err := cbRun(t, "setup", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, out, "Please enter 'local', 'reference', or 'q' to quit")
	assert.Contains(t, out, "[1/5] Detecting platform")
}

func TestSetupInteractive_AdvancedTelemetryOptIn(t *testing.T) {
	cfgDir := cbIsolate(t)
	// storage, telemetry yes, backend 1, mode canary, provider skip, UI no
	cbScriptStdin(t, "\ny\n1\ncanary\nno\nn\n")
	out, _, err := cbRun(t, "setup", "--advanced", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, out, "Advanced backend options:")
	assert.Contains(t, out, "Telemetry: on")
	assert.Contains(t, out, "canary     — inject canary tokens")
	assert.Contains(t, out, "Operating mode: canary")

	cfg := cbLoadConfig(t, cfgDir)
	assert.Equal(t, "file", cfg.Backend)
	assert.Equal(t, "canary", cfg.Mode)
	assert.True(t, cfg.Telemetry.Enabled)
	assert.Equal(t, "local", cfg.Telemetry.Sink)
}

func TestSetupInteractive_AdvancedUnknownChoiceAndTelemetryDeclined(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\n\n99\n\n\n\n")
	out, _, err := cbRun(t, "setup", "--advanced", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, out, "Telemetry: off")
	assert.Contains(t, out, "Using recommended backend \"file\"")
	cfg := cbLoadConfig(t, cfgDir)
	assert.False(t, cfg.Telemetry.Enabled)
}

func TestSetupInteractive_AdvancedTelemetryFlagSkipsPrompt(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\n9\n\n\n\n")
	out, _, err := cbRun(t, "setup", "--advanced", "--telemetry", "off", "--no-daemon-start")
	require.NoError(t, err)
	assert.NotContains(t, out, "Allow anonymous usage stats?")
	assert.Contains(t, out, "Telemetry: off")
	assert.Equal(t, "aws-sm", cbLoadConfig(t, cfgDir).Backend)
}

func TestSetupInteractive_BackendFlagWithTelemetryOff(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\nadvanced\ncustom\n\n\n")
	out, _, err := cbRun(t, "setup", "--backend", "file", "--telemetry", "OFF", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, out, "Using --backend=file")
	assert.Contains(t, out, "All modes:")
	assert.Contains(t, out, "Operating mode: custom")
	cfg := cbLoadConfig(t, cfgDir)
	assert.False(t, cfg.Telemetry.Enabled)
	assert.Equal(t, "custom", cfg.Mode)
}

func TestSetupInteractive_ModeAdvancedDefaultsToStandard(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\nadvanced\n\n\n\n")
	out, _, err := cbRun(t, "setup", "--backend", "file", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, out, "Operating mode: standard")
	assert.Equal(t, "standard", cbLoadConfig(t, cfgDir).Mode)
}

func TestSetupInteractive_UnknownModeKeepsStandard(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\nturbo\n\n\n")
	_, stderr, err := cbRun(t, "setup", "--backend", "file", "--no-daemon-start")
	require.NoError(t, err)
	assert.Contains(t, stderr, `Unknown mode "turbo" — using standard.`)
	assert.NotEqual(t, "turbo", cbLoadConfig(t, cfgDir).Mode)
}

func TestSetupInteractive_UnknownBackendRejected(t *testing.T) {
	cfgDir := cbIsolate(t)
	cbScriptStdin(t, "\n")
	_, _, err := cbRun(t, "setup", "--backend", "floppy", "--no-daemon-start")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown backend "floppy"`)
	_, statErr := os.Stat(filepath.Join(cfgDir, "config.json"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestSetupInteractive_BootstrapFailureSurfaces(t *testing.T) {
	cbIsolate(t)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("KEYLATCH_VAULT_PATH", filepath.Join(blocker, "vault"))
	cbScriptStdin(t, "\n")
	_, stderr, err := cbRun(t, "setup", "--backend", "file", "--no-daemon-start")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap failed")
	assert.Contains(t, stderr, "bootstrap:")
}

func TestSetupInteractive_KeychainUnavailableOffLinux(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("keychain is available on macOS")
	}
	cbIsolate(t)
	cbScriptStdin(t, "\n")
	_, _, err := cbRun(t, "setup", "--backend", "keychain", "--no-daemon-start")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "macOS-only")
}

func TestSetupInteractive_FullFlowSpawnsGatewayConnectAndUI(t *testing.T) {
	cbIsolate(t)
	argvLog := cbFakeSelf(t, "ok")
	// storage, accept recommended, mode, provider #1, open UI
	cbScriptStdin(t, "\ny\n\n1\ny\n")
	out, _, err := cbRunToFiles(t, "setup")
	require.NoError(t, err)
	assert.Contains(t, out, "[3/5] Gateway setup...")
	assert.Contains(t, out, "Gateway ready.")
	assert.Contains(t, out, "Running: keylatch connect ")
	assert.Contains(t, out, "Browser UI starting.")
	assert.Contains(t, out, "You're set up!")

	require.True(t, cbWaitFor(t, 10*time.Second, func() bool {
		return strings.Contains(cbReadLog(t, argvLog), "ui\n")
	}), "ui child was not started")
	argv := cbReadLog(t, argvLog)
	assert.Contains(t, argv, "gateway init\n")
	assert.Contains(t, argv, "gateway up --detach\n")
	assert.Regexp(t, `(?m)^connect \S+$`, argv)
}

func TestSetupInteractive_GatewayInitFailureIsNonFatal(t *testing.T) {
	cbIsolate(t)
	argvLog := cbFakeSelf(t, "fail-gateway-init")
	cbScriptStdin(t, "\n\n\n\n\n")
	out, stderr, err := cbRun(t, "setup", "--backend", "file")
	require.NoError(t, err)
	assert.Contains(t, stderr, "gateway init: exit status 1")
	assert.Contains(t, stderr, "retry later with: keylatch gateway init")
	assert.NotContains(t, out, "Gateway ready.")
	assert.NotContains(t, cbReadLog(t, argvLog), "gateway up")
}

func TestSetupInteractive_GatewayUpFailureIsNonFatal(t *testing.T) {
	cbIsolate(t)
	cbFakeSelf(t, "fail-gateway-up")
	cbScriptStdin(t, "\n\n\n\n\n")
	out, stderr, err := cbRun(t, "setup", "--backend", "file")
	require.NoError(t, err)
	assert.Contains(t, stderr, "gateway up: exit status 1")
	assert.Contains(t, stderr, "keylatch gateway up --detach")
	assert.NotContains(t, out, "Gateway ready.")
	assert.Contains(t, out, "You're set up!")
}

func cbBareCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	var out, errBuf bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&out)
	c.SetErr(&errBuf)
	return c, &out, &errBuf
}

func TestSetupStep4_NoConfigSkipsConnect(t *testing.T) {
	cbIsolate(t)
	c, out, errBuf := cbBareCmd()
	setupStep4ConnectProvider(c)
	assert.Contains(t, errBuf.String(), "backend config not found")
	assert.NotContains(t, out.String(), "Choose [")
}

func TestSetupStep4_ConnectByNameReportsChildFailure(t *testing.T) {
	cfgDir := cbIsolate(t)
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, config.Save(filepath.Join(cfgDir, "config.json"), config.Default()))
	argvLog := cbFakeSelf(t, "fail")
	cbScriptStdin(t, "my-provider\n")

	c, out, errBuf := cbBareCmd()
	setupStep4ConnectProvider(c)
	assert.Contains(t, out.String(), "Running: keylatch connect my-provider")
	assert.Contains(t, errBuf.String(), "keylatch connect: exit status 1")
	assert.Equal(t, "connect my-provider\n", cbReadLog(t, argvLog))
}

type cbRefRunner struct {
	stdout []byte
	code   int
	err    error
	gotBin string
	gotArg []string
}

func (r *cbRefRunner) Run(_ context.Context, bin string, args []string, _ []byte) ([]byte, []byte, int, error) {
	r.gotBin, r.gotArg = bin, args
	return r.stdout, nil, r.code, r.err
}

func cbStubResolver(t *testing.T, r *cbRefRunner) {
	t.Helper()
	old := storeNewResolver
	t.Cleanup(func() { storeNewResolver = old })
	storeNewResolver = func() *store.Resolver {
		return store.NewResolver(r).WithBinOverride("op", "/fake/bin/op")
	}
}

func TestSetupReference_ResolvesAndPersistsURI(t *testing.T) {
	cfgDir := cbIsolate(t)
	// Reference mode never bootstraps, so it relies on an existing config dir.
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	runner := &cbRefRunner{stdout: []byte("resolved-value")}
	cbStubResolver(t, runner)
	uri := "op://Private/Anthropic/api_key"
	cbScriptStdin(t, "reference\n"+uri+"\n")

	out, stderr, err := cbRun(t, "setup")
	require.NoError(t, err)
	assert.Contains(t, out, "URI format: valid")
	assert.Contains(t, out, "(dry-run)... ok")
	assert.Contains(t, out, "provider-ref URI: "+uri)
	assert.NotContains(t, out, "resolved-value", "resolved secret must never be printed")
	assert.NotContains(t, stderr, "resolved-value")
	assert.NotContains(t, stderr, "Warning")
	assert.Equal(t, "/fake/bin/op", runner.gotBin)
	assert.Equal(t, []string{"read", "--no-newline", uri}, runner.gotArg)

	assert.Equal(t, uri, cbLoadConfig(t, cfgDir).DefaultProviderRef)
	_, statErr := os.Stat(filepath.Join(cfgDir, "keyring"))
	assert.True(t, os.IsNotExist(statErr), "reference mode must not create a local keyring")
}

func TestSetupReference_ResolveFailureWarnsButSaves(t *testing.T) {
	cfgDir := cbIsolate(t)
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cbStubResolver(t, &cbRefRunner{err: errors.New("spawn failed")})
	uri := "op://Vault/Item/field"
	cbScriptStdin(t, "r\n"+uri+"\n")

	out, stderr, err := cbRun(t, "setup")
	require.NoError(t, err)
	assert.Contains(t, out, " warning")
	assert.Contains(t, stderr, "dry-run resolution failed")
	assert.Contains(t, stderr, "Ensure the external CLI is authenticated")
	assert.Equal(t, uri, cbLoadConfig(t, cfgDir).DefaultProviderRef)
}

func (r *cbRefRunner) RunEnv(ctx context.Context, bin string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, bin, args, stdin)
}
