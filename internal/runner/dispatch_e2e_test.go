//go:build !short

package runner_test

// dispatch_e2e_test.go — E2E integration tests for all four runtime modes.
//
// Build tag: !short — these tests run normally but can be skipped with -short.
// Run with: KEYLATCH_BACKEND=file go test ./internal/runner/... -run TestE2E_

import (
	"context"
	"crypto/rand"
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

// newE2ESigningKey returns a random 32-byte signing key for E2E tests.
func newE2ESigningKey() []byte {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	return key
}

// TestE2E_GatewayTyped runs an in-process mock gateway via httptest,
// calls dispatch with gateway_typed mode, and asserts that a RuntimeReceipt
// is emitted with runtime == "gateway_typed".
func TestE2E_GatewayTyped(t *testing.T) {
	// Mock gateway that responds 200 to any request.
	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockGW.Close()

	gwAddr := strings.TrimPrefix(mockGW.URL, "http://")
	key := newE2ESigningKey()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	srv := &mockTypedServer{addr: gwAddr, running: true}
	d := runner.NewGatewayTypedDriver(srv, key, storePath)

	tmpl := registry.ConnectionTemplate{
		Provider: "anthropic",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "ANTHROPIC_API_KEY", Source: "api_key"},
		},
	}

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "anthropic",
		Capability:     "chat",
		Command:        []string{"sh", "-c", "true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, tmpl)
	require.NoError(t, err, "E2E gateway_typed: Run must succeed with mock gateway")
	assert.Equal(t, string(runtime.RuntimeGatewayTyped), receipt.Runtime,
		"E2E gateway_typed: RuntimeReceipt.Runtime must be gateway_typed")
	assert.Equal(t, "allowed", receipt.PolicyDecision,
		"E2E gateway_typed: policy decision must be allowed on success")
}

// TestE2E_GatewaySdk asserts that the gateway_sdk driver:
//   - does not inject the provider API key into the child env
//   - injects OPENAI_BASE_URL pointing to the (mock) gateway
//   - emits a RuntimeReceipt with runtime == "gateway_sdk"
func TestE2E_GatewaySdk(t *testing.T) {
	const fakeKey = "sk-E2E-OPENAI-MUST-NOT-APPEAR"
	t.Setenv("OPENAI_API_KEY", fakeKey)

	// Mock gateway that responds 200.
	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockGW.Close()

	gwAddr := strings.TrimPrefix(mockGW.URL, "http://")
	key := newE2ESigningKey()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	srv := &mockGatewayServer{addr: gwAddr, running: true}
	d := runner.NewGatewaySDKDriver(srv, key, storePath)

	tmpl := registry.ConnectionTemplate{
		Provider: "openai",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewaySDK,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "OPENAI_API_KEY", Source: "api_key"},
		},
	}

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat",
		Command:        []string{"sh", "-c", "printenv"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, tmpl)
	require.NoError(t, err, "E2E gateway_sdk: Run must succeed with mock gateway")
	assert.Equal(t, string(runtime.RuntimeGatewaySDK), receipt.Runtime,
		"E2E gateway_sdk: RuntimeReceipt.Runtime must be gateway_sdk")

	output := outBuf.String()
	assert.NotContains(t, output, fakeKey,
		"E2E gateway_sdk: provider API key must not appear in child env")
	assert.Contains(t, output, "OPENAI_BASE_URL",
		"E2E gateway_sdk: OPENAI_BASE_URL must be set in child env pointing to gateway")
	assert.Contains(t, output, gwAddr,
		"E2E gateway_sdk: OPENAI_BASE_URL must point to the mock gateway address")
}

// TestE2E_DirectBrokered uses a stub broker that returns a scoped token.
// It asserts that:
//   - the child env has the scoped token (not the root credential)
//   - RuntimeReceipt.Runtime == "direct_brokered"
func TestE2E_DirectBrokered(t *testing.T) {
	vault := newClassicMockBackend()
	const rootCred = "root-cred-must-not-appear-in-child"
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte(rootCred), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const scopedToken = "scoped-ephemeral-token-from-broker-e2e"
	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte(scopedToken))
	b := &stubBroker{result: result}
	d := runner.NewBrokeredDriver(vault, b, nil)

	tmpl := registry.ConnectionTemplate{
		Provider: "myapi",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeDirectBrokered,
			Supported: []registry.RuntimeMode{registry.RuntimeDirectBrokered},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "MYAPI_KEY", Source: "api_key"},
		},
	}

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Capability:     "inject",
		Command:        []string{"sh", "-c", "printenv MYAPI_KEY"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, tmpl)
	require.NoError(t, err, "E2E direct_brokered: Run must succeed with stub broker")
	assert.Equal(t, string(runtime.RuntimeDirectBrokered), receipt.Runtime,
		"E2E direct_brokered: RuntimeReceipt.Runtime must be direct_brokered")

	output := outBuf.String()
	assert.Contains(t, output, scopedToken,
		"E2E direct_brokered: child env must contain the scoped token from broker")
	assert.NotContains(t, output, rootCred,
		"E2E direct_brokered: root credential must not reach child")
}

// TestE2E_GatewayProxy uses a stub proxy (liveness guard with check=true) and
// asserts that:
//   - HTTPS_PROXY / KEYLATCH_GATEWAY_URL env vars are set in child
//   - provider API key is absent from child env
//   - RuntimeReceipt.Runtime == "gateway_proxy"
func TestE2E_GatewayProxy(t *testing.T) {
	const canaryKey = "sk-proxy-e2e-canary-must-not-appear"
	t.Setenv("OPENROUTER_API_KEY", canaryKey)

	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv | grep -E 'KEYLATCH_GATEWAY_URL|OPENROUTER|HTTPS_PROXY' || true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err, "E2E gateway_proxy: Run must succeed with stub proxy server")
	assert.Equal(t, string(runtime.RuntimeGatewayProxy), receipt.Runtime,
		"E2E gateway_proxy: RuntimeReceipt.Runtime must be gateway_proxy")

	output := outBuf.String()
	assert.NotContains(t, output, canaryKey,
		"E2E gateway_proxy: provider API key must not appear in child env")
	assert.Contains(t, output, "KEYLATCH_GATEWAY_URL",
		"E2E gateway_proxy: KEYLATCH_GATEWAY_URL must be set in child env")
}
