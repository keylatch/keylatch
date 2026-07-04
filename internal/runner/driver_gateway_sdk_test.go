package runner_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGatewayServer implements GatewaySDKServerStarter for tests.
type mockGatewayServer struct {
	addr    string
	running bool
}

func (m *mockGatewayServer) Addr() string  { return m.addr }
func (m *mockGatewayServer) Running() bool { return m.running }

// sdkTmpl returns a minimal OpenAI ConnectionTemplate for gateway_sdk tests.
func sdkTmpl() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "openai",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewaySDK,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "OPENAI_API_KEY", Source: "api_key"},
		},
	}
}

// newSDKDriverForTest returns a gatewaySdkDriver with a temp store and random key.
func newSDKDriverForTest(t *testing.T) runner.Driver {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck

	srv := &mockGatewayServer{addr: "127.0.0.1:17880", running: true}
	return runner.NewGatewaySDKDriver(srv, key, storePath)
}

// TestGatewaySDKDriver_BaseURLInjected verifies that OPENAI_BASE_URL is set
// to the gateway address in the child environment.
func TestGatewaySDKDriver_BaseURLInjected(t *testing.T) {
	d := newSDKDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        []string{"sh", "-c", fmt.Sprintf("printenv %s", "OPENAI_BASE_URL")},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	assert.Contains(t, outBuf.String(), "127.0.0.1:17880",
		"OPENAI_BASE_URL must point to the gateway address")
}

// TestGatewaySDKDriver_SessionTokenPresent verifies KEYLATCH_GATEWAY_TOKEN is set.
func TestGatewaySDKDriver_SessionTokenPresent(t *testing.T) {
	d := newSDKDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        []string{"sh", "-c", "printenv KEYLATCH_GATEWAY_TOKEN"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	// JWT has three dot-separated segments.
	output := strings.TrimSpace(outBuf.String())
	parts := strings.Split(output, ".")
	assert.Len(t, parts, 3,
		"KEYLATCH_GATEWAY_TOKEN must be a JWT (header.payload.sig)")
}

// TestGatewaySDKDriver_ProviderAPIKeyAbsent verifies the provider API key is
// NOT present in the child environment (same security invariant as direct injection).
func TestGatewaySDKDriver_ProviderAPIKeyAbsent(t *testing.T) {
	const fakeKey = "sk-FAKE-OPENAI-KEY-MUST-NOT-LEAK"
	t.Setenv("OPENAI_API_KEY", fakeKey)

	d := newSDKDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        []string{"sh", "-c", "printenv"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	output := outBuf.String()
	// The SDK driver must strip provider API keys declared in InjectionRules.
	// OPENAI_API_KEY is declared in sdkTmpl() InjectionRules, so it must be absent.
	assert.NotContains(t, output, "OPENAI_API_KEY",
		"provider API key env var name must not appear in child environment")
	assert.NotContains(t, output, fakeKey,
		"provider API key value must not appear in child environment")
}

// TestGatewaySDKDriver_RuntimeEnvVar verifies KEYLATCH_RUNTIME is set to gateway_sdk.
func TestGatewaySDKDriver_RuntimeEnvVar(t *testing.T) {
	d := newSDKDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        []string{"sh", "-c", "printenv KEYLATCH_RUNTIME"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	assert.Contains(t, outBuf.String(), "gateway_sdk",
		"KEYLATCH_RUNTIME must be set to gateway_sdk")
}

// TestGatewaySDKDriver_ReceiptFields verifies the receipt has correct fields.
func TestGatewaySDKDriver_ReceiptFields(t *testing.T) {
	d := newSDKDriverForTest(t)

	req := runner.ExecRequest{
		ConnectionSlug: "openai",
		Capability:     "chat_completion",
		Command:        []string{"sh", "-c", "true"},
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, sdkTmpl())
	require.NoError(t, err)

	assert.Equal(t, "gateway_sdk", receipt.Runtime)
	assert.Equal(t, "allowed", receipt.PolicyDecision)
	assert.Equal(t, "openai", receipt.Provider)
}
