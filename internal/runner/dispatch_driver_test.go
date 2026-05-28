package runner_test

// dispatch_driver_test.go holds the per-mode DispatchRunner driver-wiring tests
// (TestDispatch_<Mode>) referenced by T01–T04.
// These use stub implementations and don't require external processes.

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- shared helpers --------------------------------------------------------

// newSigningKey returns a random 32-byte signing key for tests.
func newSigningKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	return key
}

// mockTypedServer implements runner.GatewayTypedServerStarter.
type mockTypedServer struct {
	addr    string
	running bool
}

func (m *mockTypedServer) Addr() string  { return m.addr }
func (m *mockTypedServer) Running() bool { return m.running }

// gatewayTypedTmpl builds a ConnectionTemplate with gateway_typed support.
func gatewayTypedTmpl(provider string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: provider,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "api_key"},
		},
	}
}

// ---- T01: TestDispatch_GatewayTyped ----------------------------------------

// TestDispatch_GatewayTyped_DriverRegistered verifies that the gateway_typed
// driver is registered and reachable via DispatchRunner (no ErrUnknownRuntime).
func TestDispatch_GatewayTyped_DriverRegistered(t *testing.T) {
	// Spin up an httptest gateway that responds 200 /health so the driver
	// doesn't fail due to gateway being unreachable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest server address WITHOUT the http:// scheme.
	gwAddr := strings.TrimPrefix(srv.URL, "http://")

	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	typedSrv := &mockTypedServer{addr: gwAddr, running: true}
	d := runner.NewGatewayTypedDriver(typedSrv, key, storePath)

	dr := runner.DispatchRunner{
		Guard: nil,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeGatewayTyped): d,
		},
	}

	// anthropic uses gateway_typed as preferred mode.
	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Command:        []string{"sh", "-c", "true"},
		Runtime:        string(runtime.RuntimeGatewayTyped),
		Stderr:         &strings.Builder{},
	}
	// anthropic is in the allowlist via ExtraAllowedPrefixes.
	req.ExtraAllowedPrefixes = []string{"sh"}

	_, err := dr.Run(context.Background(), req)
	// Must NOT be ErrUnknownRuntime.
	assert.False(t, errors.Is(err, runner.ErrUnknownRuntime),
		"gateway_typed driver must be registered — ErrUnknownRuntime must not be returned")
}

// TestDispatch_GatewayTyped_GatewayNotRunning verifies ErrGatewayNotRunning
// is returned when the gateway server reports not running.
func TestDispatch_GatewayTyped_GatewayNotRunning(t *testing.T) {
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	typedSrv := &mockTypedServer{addr: "127.0.0.1:7878", running: false}
	d := runner.NewGatewayTypedDriver(typedSrv, key, storePath)

	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Command:        []string{"sh", "-c", "true"},
	}
	_, err := d.Run(context.Background(), req, gatewayTypedTmpl("anthropic"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrGatewayNotRunning),
		"gateway_typed must return ErrGatewayNotRunning when server reports not running")
}

// TestDispatch_GatewayTyped_ReceiptEmitted verifies a RuntimeReceipt is emitted
// with runtime == "gateway_typed".
func TestDispatch_GatewayTyped(t *testing.T) {
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	typedSrv := &mockTypedServer{addr: "127.0.0.1:7878", running: true}
	d := runner.NewGatewayTypedDriver(typedSrv, key, storePath)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Command:        []string{"sh", "-c", "true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, gatewayTypedTmpl("anthropic"))
	require.NoError(t, err)
	assert.Equal(t, "gateway_typed", receipt.Runtime)
	assert.Equal(t, "allowed", receipt.PolicyDecision)
}

// TestDispatch_GatewayTyped_APIKeyAbsent verifies the provider API key
// (TEST_API_KEY in the gatewayTypedTmpl InjectionRules) is absent from the
// child environment when using the gateway_typed driver.
func TestDispatch_GatewayTyped_APIKeyAbsent(t *testing.T) {
	const canary = "sk-canary-must-not-appear"
	t.Setenv("TEST_API_KEY", canary)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gwAddr := strings.TrimPrefix(srv.URL, "http://")
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	typedSrv := &mockTypedServer{addr: gwAddr, running: true}
	d := runner.NewGatewayTypedDriver(typedSrv, key, storePath)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Command:        []string{"sh", "-c", "printenv"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, gatewayTypedTmpl("anthropic"))
	require.NoError(t, err)

	output := outBuf.String()
	assert.NotContains(t, output, canary,
		"provider API key must not be present in child environment (gateway_typed canary)")
}

// TestDispatch_GatewayTyped_StaleTokenReplaced verifies that when
// KEYLATCH_GATEWAY_TOKEN is already set in the parent environment (stale),
// the child receives the freshly minted token, not the stale one.
// This exercises the appendOrReplace behaviour for KEYLATCH_GATEWAY_TOKEN.
func TestDispatch_GatewayTyped_StaleTokenReplaced(t *testing.T) {
	const staleToken = "stale-old-token-must-not-reach-child"
	t.Setenv("KEYLATCH_GATEWAY_TOKEN", staleToken)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gwAddr := strings.TrimPrefix(srv.URL, "http://")
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	typedSrv := &mockTypedServer{addr: gwAddr, running: true}
	d := runner.NewGatewayTypedDriver(typedSrv, key, storePath)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Command:        []string{"sh", "-c", "printenv KEYLATCH_GATEWAY_TOKEN"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, gatewayTypedTmpl("anthropic"))
	require.NoError(t, err)

	output := strings.TrimSpace(outBuf.String())
	// The stale token must not appear in the child env.
	assert.NotContains(t, output, staleToken,
		"stale KEYLATCH_GATEWAY_TOKEN must be replaced by the newly minted token")
	// The child must receive a valid JWT (3 dot-separated segments).
	parts := strings.Split(output, ".")
	assert.Len(t, parts, 3,
		"KEYLATCH_GATEWAY_TOKEN in child must be a newly minted JWT (header.payload.sig)")
}

// ---- T02: TestDispatch_GatewaySdk ------------------------------------------

// TestDispatch_GatewaySdk_DriverRegistered verifies the gateway_sdk driver
// is registered and does not return ErrUnknownRuntime.
func TestDispatch_GatewaySdk_DriverRegistered(t *testing.T) {
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	srv := &mockGatewayServer{addr: "127.0.0.1:17880", running: true}
	d := runner.NewGatewaySDKDriver(srv, key, storePath)

	dr := runner.DispatchRunner{
		Guard: nil,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeGatewaySDK): d,
		},
	}

	req := runner.ExecRequest{
		ConnectionSlug:       "openai",
		Command:              []string{"sh", "-c", "true"},
		Runtime:              string(runtime.RuntimeGatewaySDK),
		ExtraAllowedPrefixes: []string{"sh"},
		Stderr:               &strings.Builder{},
	}

	_, err := dr.Run(context.Background(), req)
	assert.False(t, errors.Is(err, runner.ErrUnknownRuntime),
		"gateway_sdk driver must be registered — ErrUnknownRuntime must not be returned")
}

// TestDispatch_GatewaySdk_GatewayNotRunning verifies ErrGatewayNotRunning when
// the gateway server reports not running.
func TestDispatch_GatewaySdk_GatewayNotRunning(t *testing.T) {
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	srv := &mockGatewayServer{addr: "127.0.0.1:7878", running: false}
	d := runner.NewGatewaySDKDriver(srv, key, storePath)

	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Command:        []string{"sh", "-c", "true"},
	}
	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrGatewayNotRunning),
		"gateway_sdk must return ErrGatewayNotRunning when server reports not running")
}

// TestDispatch_GatewaySdk_ProviderKeyAbsent verifies the provider API key
// is absent from the child environment (canary test).
func TestDispatch_GatewaySdk(t *testing.T) {
	const fakeKey = "sk-FAKE-OPENAI-KEY-CANARY-SDK"
	t.Setenv("OPENAI_API_KEY", fakeKey)

	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	srv := &mockGatewayServer{addr: "127.0.0.1:17880", running: true}
	d := runner.NewGatewaySDKDriver(srv, key, storePath)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Command:        []string{"sh", "-c", "printenv"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	output := outBuf.String()
	assert.NotContains(t, output, fakeKey,
		"provider API key must not be present in child environment (gateway_sdk canary)")
	assert.Contains(t, output, "OPENAI_BASE_URL",
		"OPENAI_BASE_URL must be set in child env pointing to the gateway")
}

// ---- T03: TestDispatch_DirectBrokered --------------------------------------

// TestDispatch_DirectBrokered_DriverRegistered verifies the direct_brokered
// driver is registered and does not return ErrUnknownRuntime.
func TestDispatch_DirectBrokered_DriverRegistered(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const ephemeralToken = "ephemeral-token-xyz"
	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte(ephemeralToken))
	b := &stubBroker{result: result}
	d := runner.NewBrokeredDriver(vault, b, nil)

	dr := runner.DispatchRunner{
		Guard: nil,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeDirectBrokered): d,
		},
	}

	req := runner.ExecRequest{
		ConnectionSlug:       "myapi",
		Command:              []string{"sh", "-c", "true"},
		Runtime:              string(runtime.RuntimeDirectBrokered),
		ExtraAllowedPrefixes: []string{"sh"},
		Stderr:               &strings.Builder{},
	}

	_, err := dr.Run(context.Background(), req)
	assert.False(t, errors.Is(err, runner.ErrUnknownRuntime),
		"direct_brokered driver must be registered — ErrUnknownRuntime must not be returned")
}

// TestDispatch_DirectBrokered verifies the brokered driver is called and
// the child env has the scoped token, not the root credential.
func TestDispatch_DirectBrokered(t *testing.T) {
	vault := newClassicMockBackend()
	const rootCred = "root-secret-must-not-leak"
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte(rootCred), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const ephemeralToken = "ephemeral-scoped-token-brokered"
	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte(ephemeralToken))
	b := &stubBroker{result: result}
	d := runner.NewBrokeredDriver(vault, b, nil)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "printenv TEST_API_KEY"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.NoError(t, err)
	assert.Equal(t, "direct_brokered", receipt.Runtime)

	output := outBuf.String()
	assert.Contains(t, output, ephemeralToken,
		"child must receive ephemeral scoped token")
	assert.NotContains(t, output, rootCred,
		"root credential must not leak into child env (S-RM-3)")
}

// TestDispatch_DirectBrokered_UnsupportedRuntime verifies ErrUnsupportedRuntime
// is returned (no nil panic) when the template doesn't support direct_brokered.
func TestDispatch_DirectBrokered_UnsupportedRuntime(t *testing.T) {
	vault := newClassicMockBackend()
	var nilBroker *stubBroker // typed nil — ErrUnsupportedRuntime fires before any broker call
	d := runner.NewBrokeredDriver(vault, nilBroker, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "unsupported",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, brokeredTmplNoSupport())
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrUnsupportedRuntime),
		"nil broker + unsupported template must return ErrUnsupportedRuntime, not panic")
}

// ---- T04: TestDispatch_GatewayProxy ----------------------------------------

// TestDispatch_GatewayProxy_DriverRegistered verifies the gateway_proxy driver
// is registered and does not return ErrUnknownRuntime.
func TestDispatch_GatewayProxy_DriverRegistered(t *testing.T) {
	proxyDriver, _ := newProxyDriverForTest(t)

	dr := runner.DispatchRunner{
		Guard: nil,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeGatewayProxy): proxyDriver,
		},
	}

	req := runner.ExecRequest{
		ConnectionSlug:       "testprovider",
		Command:              []string{"sh", "-c", "true"},
		Runtime:              string(runtime.RuntimeGatewayProxy),
		ExtraAllowedPrefixes: []string{"sh"},
		Stderr:               &strings.Builder{},
	}

	_, err := dr.Run(context.Background(), req)
	assert.False(t, errors.Is(err, runner.ErrUnknownRuntime),
		"gateway_proxy driver must be registered — ErrUnknownRuntime must not be returned")
}

// TestDispatch_GatewayProxy verifies the proxy driver injects HTTPS_PROXY-style
// env vars and strips the provider API key from the child env.
func TestDispatch_GatewayProxy(t *testing.T) {
	const canaryKey = "sk-proxy-canary-must-not-appear"
	t.Setenv("OPENROUTER_API_KEY", canaryKey)

	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv | grep -E 'KEYLATCH_GATEWAY_URL|OPENROUTER' || true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	output := outBuf.String()
	assert.NotContains(t, output, canaryKey,
		"provider API key must not be present in child environment (gateway_proxy)")
	assert.Contains(t, output, "KEYLATCH_GATEWAY_URL",
		"KEYLATCH_GATEWAY_URL must be set in child env")
}

// TestDispatch_GatewayProxy_NotRunning verifies the liveness guard returns
// ErrProxyNotRunning when the check function says the proxy is not running.
func TestDispatch_GatewayProxy_NotRunning(t *testing.T) {
	key := newSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	inner, _ := newProxyDriverForTest(t)
	_ = key
	_ = storePath
	guarded := runner.WithLivenessGuard(inner, func() bool { return false }, runner.ErrProxyNotRunning)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := guarded.Run(context.Background(), req, proxyTmpl())
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrProxyNotRunning),
		"guarded proxy driver must return ErrProxyNotRunning when check returns false")
}
