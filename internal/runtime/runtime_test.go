package runtime_test

import (
	"context"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllModesCount(t *testing.T) {
	// direct_classic_sandboxed reinstated as a new sibling mode.
	// direct_classic remains permanently removed.
	// Five modes: gateway_typed, gateway_sdk, direct_brokered, gateway_proxy,
	// direct_classic_sandboxed.
	assert.Len(t, runtime.AllModes, 5, "AllModes must contain exactly 5 runtime modes")
}

func TestAllModesUnique(t *testing.T) {
	seen := map[runtime.RuntimeMode]bool{}
	for _, m := range runtime.AllModes {
		assert.False(t, seen[m], "duplicate mode %q in AllModes", m)
		seen[m] = true
	}
}

func TestNoUnrestrictedMode(t *testing.T) {
	for _, m := range runtime.AllModes {
		assert.False(t,
			strings.Contains(string(m), "unrestricted"),
			"AllModes must not contain any unrestricted mode; found %q", m)
	}
}

// TestIsRawCredentialMode is the raw-credential session gate's raw-exposure boundary internal/cli's
// RequireVerifiedSession relies on to decide which `run` invocations need
// session corroboration. Only direct/brokered modes inject a raw provider
// secret into the child process; gateway/proxy modes only ever hand over a
// scoped keylatch session token.
func TestIsRawCredentialMode(t *testing.T) {
	cases := []struct {
		mode   runtime.RuntimeMode
		isRaw  bool
		reason string
	}{
		{runtime.RuntimeDirectBrokered, true, "direct_brokered injects a provider-ephemeral credential"},
		{runtime.RuntimeDirectClassicSandboxed, true, "direct_classic_sandboxed injects the provider_root credential into a sandboxed env"},
		{runtime.RuntimeGatewayTyped, false, "gateway_typed only ever hands over a keylatch session token"},
		{runtime.RuntimeGatewaySDK, false, "gateway_sdk only ever hands over a keylatch session token"},
		{runtime.RuntimeGatewayProxy, false, "gateway_proxy only ever hands over a keylatch session token"},
		{runtime.RuntimeMode("bogus"), false, "unknown modes have no registered driver, so no credential of any shape reaches the child"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.isRaw, runtime.IsRawCredentialMode(tc.mode), tc.reason)
	}
}

// TestIsRawCredentialMode_MatchesResolvedShape cross-checks IsRawCredentialMode
// against the CredentialShape Resolve() actually assigns for the four modes
// known to the registry package, so the two classifications can never
// silently drift for those modes. (direct_classic_sandboxed is intentionally
// excluded here: it is not part of registry.RuntimeMode/the Resolve()
// fallback hierarchy — it is only ever selected directly via the CLI
// --runtime flag, bypassing Resolve() entirely; see internal/cli/root.go's
// DispatchRunner wiring.)
func TestIsRawCredentialMode_MatchesResolvedShape(t *testing.T) {
	tmpl := buildTmpl(
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewayTyped,
		registry.RuntimeGatewaySDK,
		registry.RuntimeDirectBrokered,
		registry.RuntimeGatewayProxy,
	)
	for _, m := range []runtime.RuntimeMode{
		runtime.RuntimeGatewayTyped,
		runtime.RuntimeGatewaySDK,
		runtime.RuntimeDirectBrokered,
		runtime.RuntimeGatewayProxy,
	} {
		dec, err := runtime.Resolve(context.Background(), runtime.ResolveRequest{RequestedMode: m}, tmpl)
		require.NoError(t, err)
		wantRaw := dec.CredentialShape != runtime.DeliveryKeylatchSessionToken
		assert.Equal(t, wantRaw, runtime.IsRawCredentialMode(m),
			"IsRawCredentialMode(%q) must match whether Resolve() assigns a non-token CredentialShape", m)
	}
}
