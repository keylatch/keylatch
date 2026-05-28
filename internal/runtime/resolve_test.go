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
	// Provider only supports gateway_typed; caller asks for direct_brokered.
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeDirectBrokered,
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
	// Only direct_brokered and gateway_proxy are supported.
	// Hierarchy prefers direct_brokered before gateway_proxy.
	tmpl := buildTmpl(
		"",
		registry.RuntimeGatewayProxy,
		registry.RuntimeDirectBrokered,
	)
	req := runtime.ResolveRequest{ConnectionSlug: "aws"}
	d, err := runtime.Resolve(context.Background(), req, tmpl)
	require.NoError(t, err)
	assert.Equal(t, runtime.RuntimeDirectBrokered, d.Mode,
		"direct_brokered must be selected before gateway_proxy in the fallback hierarchy")
}

// TestResolve_ClassicSandboxedNotRemoved verifies that direct_classic_sandboxed
// is no longer a removed mode after EPIC-24 reinstated it.
// Requesting it on a template that does not list it in Supported returns
// ErrModeNotSupported (not ErrModeRemoved).
func TestResolve_ClassicSandboxedNotRemoved(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
	)
	req := runtime.ResolveRequest{
		RequestedMode:  runtime.RuntimeDirectClassicSandboxed,
		ConnectionSlug: "legacy",
	}
	_, err := runtime.Resolve(context.Background(), req, tmpl)
	require.Error(t, err)
	// Must be ErrModeNotSupported (provider doesn't list it), NOT ErrModeRemoved.
	assert.True(t, errors.Is(err, runtime.ErrModeNotSupported),
		"direct_classic_sandboxed is active (EPIC-24); template that omits it returns ErrModeNotSupported")
	assert.False(t, errors.Is(err, runtime.ErrModeRemoved),
		"direct_classic_sandboxed must not return ErrModeRemoved — it is no longer removed")
}

// TestResolve_RemovedDirectClassicReturnsErrModeRemoved verifies that
// requesting direct_classic (removed in T-10-03) returns ErrModeRemoved.
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
		"direct_classic must return ErrModeRemoved after T-10-03")
}
