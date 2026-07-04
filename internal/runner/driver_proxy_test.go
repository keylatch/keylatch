package runner_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proxyTmpl returns a minimal ConnectionTemplate for gateway_proxy tests.
func proxyTmpl() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "testprovider",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayProxy,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayProxy},
		},
	}
}

// newProxyDriverForTest returns a proxyDriver configured with a temp store path
// and a random 32-byte signing key.
func newProxyDriverForTest(t *testing.T) (runner.Driver, string) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	key := make([]byte, 32)
	rand.Read(key)

	srv := &proxy.Server{
		Addr: "127.0.0.1:17879", // use a non-default port for tests
	}
	d := runner.NewProxyDriver(srv, key, storePath, "")
	return d, storePath
}

// TestProxyDriver_ProviderAPIKeyAbsentFromChildEnv is the core security invariant:
// the child subprocess env must NOT contain any provider API keys — only
// KEYLATCH_GATEWAY_URL, KEYLATCH_SESSION_TOKEN, and KEYLATCH_RUNTIME.
func TestProxyDriver_ProviderAPIKeyAbsentFromChildEnv(t *testing.T) {
	const providerKey = "sk-or-PROVIDER-KEY-MUST-NOT-LEAK"

	// Set a fake provider API key in the parent process env temporarily.
	// The proxy driver must NOT forward it to the child.
	t.Setenv("OPENROUTER_API_KEY", providerKey)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-FAKE-KEY-MUST-NOT-LEAK")

	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv | grep -E 'OPENROUTER|ANTHROPIC' || true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	// Provider API keys must not appear in child env output.
	assert.NotContains(t, outBuf.String(), providerKey,
		"provider API key must not be present in child environment")
	assert.NotContains(t, outBuf.String(), "sk-ant-FAKE-KEY-MUST-NOT-LEAK",
		"provider API key must not be present in child environment")
}

// TestProxyDriver_KeylatchEnvVarsPresent verifies that KEYLATCH_GATEWAY_URL,
// KEYLATCH_SESSION_TOKEN, and KEYLATCH_RUNTIME are present in the child env.
func TestProxyDriver_KeylatchEnvVarsPresent(t *testing.T) {
	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv KEYLATCH_GATEWAY_URL && printenv KEYLATCH_SESSION_TOKEN && printenv KEYLATCH_RUNTIME"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	output := outBuf.String()
	// printenv outputs the value only. KEYLATCH_GATEWAY_URL should contain the proxy addr.
	assert.Contains(t, output, "127.0.0.1:17879",
		"KEYLATCH_GATEWAY_URL must point to the proxy address")
	// KEYLATCH_RUNTIME must be "gateway_proxy".
	assert.Contains(t, output, "gateway_proxy",
		"KEYLATCH_RUNTIME must be set to gateway_proxy")
}

// TestProxyDriver_CAPathInjected verifies that when caPath is set, the child
// env contains SSL CA env vars pointing to the CA cert.
func TestProxyDriver_CAPathInjected(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	caPath := filepath.Join(dir, "ca.pem")
	// Create a dummy CA cert file.
	require.NoError(t, os.WriteFile(caPath, []byte("DUMMY CA"), 0o644))

	key := make([]byte, 32)
	rand.Read(key)

	srv := &proxy.Server{Addr: "127.0.0.1:17879"}
	d := runner.NewProxyDriver(srv, key, storePath, caPath)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv SSL_CERT_FILE"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	assert.Contains(t, outBuf.String(), caPath,
		"SSL_CERT_FILE must point to the CA cert path")
}

// TestProxyDriver_ReceiptHasGatewayProxyRuntime verifies the receipt runtime field.
func TestProxyDriver_ReceiptHasGatewayProxyRuntime(t *testing.T) {
	d, _ := newProxyDriverForTest(t)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "true"},
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)
	assert.Equal(t, "gateway_proxy", receipt.Runtime)
}

// TestProxyDriver_EmptyCommand_ReturnsError verifies that an empty command
// returns an error immediately without trying to contact the proxy server.
func TestProxyDriver_EmptyCommand_ReturnsError(t *testing.T) {
	d, _ := newProxyDriverForTest(t)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{}, // empty
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty command",
		"empty command must produce a descriptive error")
}

// TestProxyDriver_NilServer_UsesDefaultAddr verifies that a nil proxy.Server
// falls back to the default proxy address (127.0.0.1:7879 in the test driver).
// The child env must still contain KEYLATCH_GATEWAY_URL.
func TestProxyDriver_NilServer_FallsBackToDefaultAddr(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	key := make([]byte, 32)
	rand.Read(key)

	// Pass a Server with empty Addr — should fall back to default "127.0.0.1:7879"
	srv := &proxy.Server{Addr: ""}
	d := runner.NewProxyDriver(srv, key, storePath, "")

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv KEYLATCH_GATEWAY_URL"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)
	assert.Contains(t, outBuf.String(), "7879",
		"KEYLATCH_GATEWAY_URL must contain the default proxy port when Addr is empty")
}

// TestProxyDriver_ProviderKeyAbsentCanary_FromParentEnv is a canary test that
// verifies the child process env does NOT contain a specific provider key string.
// This mirrors the five-mode canary requirement from the test spec.
func TestProxyDriver_ProviderKeyAbsent_Canary(t *testing.T) {
	const canaryKey = "sk-canary-must-not-appear-in-child-8675309"
	t.Setenv("OPENROUTER_API_KEY", canaryKey)
	t.Setenv("ANTHROPIC_API_KEY", canaryKey)

	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv | grep " + canaryKey + " || true"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	assert.NotContains(t, outBuf.String(), canaryKey,
		"canary provider key must not appear in child process environment (gateway_proxy mode)")
}

// TestProxyDriver_ExtraEnvVars_DenylistsProviderKeys verifies that operator
// --extra names matching a well-known provider credential env var are
// denied, even though --extra is normally honored for arbitrary names.
// This closes the gap where --extra OPENAI_API_KEY would otherwise leak the
// real parent-process secret into the gateway_proxy child (defeating S9-15).
func TestProxyDriver_ExtraEnvVars_DenylistsProviderKeys(t *testing.T) {
	const realSecret = "sk-real-parent-secret-must-not-leak-via-extra"
	t.Setenv("OPENAI_API_KEY", realSecret)
	t.Setenv("MY_CUSTOM_TOKEN", "custom-value-should-pass-through")

	d, _ := newProxyDriverForTest(t)

	var outBuf strings.Builder
	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"sh", "-c", "printenv OPENAI_API_KEY; printenv MY_CUSTOM_TOKEN"},
		ExtraEnvVars:   []string{"OPENAI_API_KEY", "MY_CUSTOM_TOKEN"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, proxyTmpl())
	require.NoError(t, err)

	assert.NotContains(t, outBuf.String(), realSecret,
		"--extra must not be able to leak a known provider credential env var into the child")
	assert.Contains(t, outBuf.String(), "custom-value-should-pass-through",
		"--extra must still pass through non-denylisted names")
}
