package runtime_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTmpl constructs a minimal ConnectionTemplate for resolve tests.
func buildTmpl(preferred registry.RuntimeMode, supported ...registry.RuntimeMode) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: preferred,
			Supported: supported,
		},
	}
}

func TestResolve_ExplicitModeMatch(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewaySDK,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeGatewaySDK,
		ConnectionSlug: "openrouter",
	}
	d, err := runtime.Resolve(context.Background(), req, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeGatewaySDK, d.Mode)
	assert.Equal(t, "explicit request", d.Reason)
}

func TestResolve_UnsupportedModeReturnsError(t *testing.T) {
	// Provider only supports gateway_typed; caller asks for minted.
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeMinted,
		ConnectionSlug: "openrouter",
	}
	_, err := runtime.Resolve(context.Background(), req, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runtime.ErrModeNotSupported),
		"ErrModeNotSupported must be returned when requested mode is absent from supported set")
}

func TestResolve_DefaultFallsBackToPreferred(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeGatewaySDK,
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewaySDK,
	)
	req := runtime.ResolveRequest{ConnectionSlug: "openrouter"}
	d, err := runtime.Resolve(context.Background(), req, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeGatewaySDK, d.Mode)
	assert.Equal(t, "provider preferred", d.Reason)
}

func TestResolve_FallbackHierarchyWhenNoPreferred(t *testing.T) {
	// No preferred set, only gateway_proxy supported.
	tmpl := buildTmpl(
		"", // no preferred
		registry.RuntimeGatewayProxy,
	)
	req := runtime.ResolveRequest{ConnectionSlug: "legacy"}
	d, err := runtime.Resolve(context.Background(), req, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeGatewayProxy, d.Mode)
	assert.Equal(t, "fallback hierarchy", d.Reason)
}

func TestResolve_NoSupportedModesReturnsError(t *testing.T) {
	tmpl := buildTmpl("") // no preferred, no supported
	req := runtime.ResolveRequest{ConnectionSlug: "mystery"}
	_, err := runtime.Resolve(context.Background(), req, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runtime.ErrModeNotSupported))
}

func TestResolve_FallbackHierarchyOrder(t *testing.T) {
	// Only minted and gateway_proxy are supported.
	// Hierarchy prefers minted before gateway_proxy.
	tmpl := buildTmpl(
		"",
		registry.RuntimeGatewayProxy,
		registry.RuntimeMinted,
	)
	req := runtime.ResolveRequest{ConnectionSlug: "aws"}
	d, err := runtime.Resolve(context.Background(), req, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeMinted, d.Mode,
		"minted must be selected before gateway_proxy in the fallback hierarchy")
}

// TestRuntimeDefaultsToTemplate checks that an empty --runtime lets the
// template's preferred mode apply.
func TestRuntimeDefaultsToTemplate(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeMinted,
		registry.RuntimeGatewayTyped,
		registry.RuntimeMinted,
	)
	d, err := runtime.Resolve(context.Background(), runtime.ResolveRequest{ConnectionSlug: "github-app"}, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeMinted, d.Mode)
	assert.Equal(t, "provider preferred", d.Reason)
	assert.Equal(t, runtime.DeliveryProviderEphemeral, d.CredentialShape)
}

// TestDirectBrokeredIsRenamed checks that the old name is refused with a
// pointer to the new one.
func TestDirectBrokeredIsRenamed(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeMinted,
		registry.RuntimeMinted,
	)
	_, err := runtime.Resolve(context.Background(), runtime.ResolveRequest{RequestedMode: runtime.RuntimeMode("direct_brokered")}, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runtime.ErrModeRemoved))
	assert.Contains(t, err.Error(), "--runtime minted")
}

// TestClassicSandboxedRemoved verifies that direct_classic_sandboxed is gone
// without an alias: it is not a runtime mode and a request for it is not served.
func TestClassicSandboxedRemoved(t *testing.T) {
	for _, m := range runtime.AllModes {
		assert.NotEqual(t, "direct_classic_sandboxed", string(m))
	}
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeMode("direct_classic_sandboxed"),
		ConnectionSlug: "legacy",
	}
	_, err := runtime.Resolve(context.Background(), req, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runtime.ErrModeNotSupported))
	assert.False(t, errors.Is(err, runtime.ErrModeRemoved), "no removal alias is kept")
}

// TestRuntimeList locks the runtime modes that exist.
func TestRuntimeList(t *testing.T) {
	assert.Equal(t, []runtime.RuntimeMode{
		runtime.RuntimeGatewayTyped,
		runtime.RuntimeGatewaySDK,
		runtime.RuntimeMinted,
		runtime.RuntimeGatewayProxy,
	}, runtime.AllModes)
}

// TestResolve_RemovedDirectClassicReturnsErrModeRemoved verifies that
// requesting direct_classic (removed) returns ErrModeRemoved.
func TestResolve_RemovedDirectClassicReturnsErrModeRemoved(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeMode("direct_classic"),
		ConnectionSlug: "legacy",
	}
	_, err := runtime.Resolve(context.Background(), req, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runtime.ErrModeRemoved),
		"direct_classic must return ErrModeRemoved")
}
