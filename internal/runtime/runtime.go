// Package runtime defines RuntimeMode for keylatch credential access control.
// The runtime modes are gateway_typed, gateway_sdk, minted and gateway_proxy.
// gateway_proxy is not available in this release.
package runtime

import "errors"

// RuntimeMode identifies how the CLI interacts with credentials.
type RuntimeMode string

const (
	RuntimeGatewayTyped RuntimeMode = "gateway_typed"
	RuntimeGatewaySDK   RuntimeMode = "gateway_sdk"
	RuntimeGatewayProxy RuntimeMode = "gateway_proxy"
	// RuntimeMinted runs the command with a short-lived credential minted for
	// it and revoked when it exits.
	RuntimeMinted RuntimeMode = "minted"
)

// AllModes is the closed set used by the matrix builder in tests.
// A new constant MUST be added here; failing to do so breaks TestRuntimeMatrixComplete.
var AllModes = []RuntimeMode{
	RuntimeGatewayTyped,
	RuntimeGatewaySDK,
	RuntimeMinted,
	RuntimeGatewayProxy,
}

// removedModes maps removed mode names to actionable hint strings.
// Resolve() checks this before the supported set so removed modes return
// ErrModeRemoved (exit 5) with a clear hint.
var removedModes = map[string]string{
	"direct_classic":  "mode removed in v1.0.0. Use: --runtime gateway_typed",
	"direct_brokered": "mode renamed. Use: --runtime minted",
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
	case RuntimeMinted:
		return true
	default:
		return false
	}
}
