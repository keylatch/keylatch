// Package runtime defines RuntimeMode for keylatch credential access control.
// v1.0.0 base set: gateway_typed, gateway_sdk, direct_brokered, gateway_proxy.
// direct_classic_sandboxed reinstated as a new sibling mode backed by
// bwrap (Linux) / sandbox-exec (macOS). direct_classic remains permanently removed.
package runtime

import "errors"

// RuntimeMode identifies how the CLI interacts with credentials.
// v1.0.0 set: gateway_typed, gateway_sdk, direct_brokered, gateway_proxy,
// plus direct_classic_sandboxed.
type RuntimeMode string

const (
	RuntimeGatewayTyped           RuntimeMode = "gateway_typed"
	RuntimeGatewaySDK             RuntimeMode = "gateway_sdk"
	RuntimeDirectBrokered         RuntimeMode = "direct_brokered"
	RuntimeGatewayProxy           RuntimeMode = "gateway_proxy"
	RuntimeDirectClassicSandboxed RuntimeMode = "direct_classic_sandboxed"
)

// AllModes is the closed set used by the matrix builder in tests.
// A new constant MUST be added here; failing to do so breaks TestRuntimeMatrixComplete.
var AllModes = []RuntimeMode{
	RuntimeGatewayTyped,
	RuntimeGatewaySDK,
	RuntimeDirectBrokered,
	RuntimeGatewayProxy,
	RuntimeDirectClassicSandboxed,
}

// removedModes maps removed mode names to actionable hint strings.
// Resolve() checks this before the supported set so removed modes return
// ErrModeRemoved (exit 5) with a clear hint.
// Note: direct_classic_sandboxed is NOT in this map — it is active.
var removedModes = map[string]string{
	"direct_classic": "mode removed in v1.0.0. Use: --runtime gateway_typed",
}

// ErrModeRemoved is returned when the caller requests a runtime mode that was
// removed in v1.0.0. Callers should exit with exitcode.RuntimeNotAvailable (5).
var ErrModeRemoved = errors.New("runtime: mode removed — see hint for replacement")

// IsRemovedMode reports whether the given mode string was removed in v1.0.0.
// Returns the hint string (non-empty) when the mode is removed.
// Used by CLI commands to gate removed modes before the general "unknown mode"
// error path, so they receive exit 5 (RuntimeNotAvailable) rather than exit 1.
func IsRemovedMode(mode string) (hint string, removed bool) {
	hint, removed = removedModes[mode]
	return hint, removed
}

// IsRawCredentialMode reports whether m injects a raw provider credential
// directly into the child process environment, as opposed to the gateway/proxy
// modes where the child only ever receives a scoped keylatch session token
// (DeliveryKeylatchSessionToken) and never sees the actual secret value.
//
// docker-server-security hardening (raw-credential session gate scoping): this is the
// exact boundary internal/cli's RequireVerifiedSession uses to decide whether
// a command needs positive session corroboration before proceeding — gateway
// mode gives an unverified/spoofed session nothing of value, so it is left
// unrestricted; direct/brokered modes hand over the real secret, so those
// paths fail closed by default.
//
// Unrecognized mode strings return false: DispatchRunner has no driver
// registered for an unknown mode, so no credential of any shape reaches the
// child regardless — the existing mode validation (isKnownMode in
// internal/cli) is what surfaces a clear, actionable error for a typo'd
// --runtime value instead of a confusing security-block message.
func IsRawCredentialMode(m RuntimeMode) bool {
	switch m {
	case RuntimeDirectBrokered, RuntimeDirectClassicSandboxed:
		return true
	default:
		return false
	}
}
