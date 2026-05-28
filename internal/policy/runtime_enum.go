// Package policy implements the keylatch policy engine.
// runtime_enum.go defines the closed set of valid runtime modes and
// provides a parser that rejects removed or unknown names (FIND2-023).
package policy

import "fmt"

// RuntimeMode is the canonical type for execution mode values.
type RuntimeMode string

const (
	RuntimeGatewayTyped   RuntimeMode = "gateway_typed"
	RuntimeGatewaySDK     RuntimeMode = "gateway_sdk"
	RuntimeDirectBrokered RuntimeMode = "direct_brokered"
	// RuntimeDirectClassic is the 0.1.0 non-sandboxed direct injection mode.
	RuntimeDirectClassic RuntimeMode = "direct_classic"
	RuntimeGatewayProxy  RuntimeMode = "gateway_proxy"
)

// removedRuntimes is the set of names that have been removed (FIND2-023).
// ValidateRuntimeMode returns a descriptive error pointing to the migration table.
var removedRuntimes = map[string]bool{
	"direct_run":     true,
	"local_gateway":  true,
	"hosted_gateway": true,
}

// plannedRuntimes is the set of names that are declared but not yet available.
// They are accepted by the parser (to avoid confusing "unknown" errors) but
// the driver returns ErrModeNotAvailable at runtime.
var plannedRuntimes = map[string]bool{
	"direct_classic_sandboxed": true, // planned for 0.2.0
}

// ValidateRuntimeMode returns nil for a valid runtime mode.
// It returns a descriptive error for removed names and unknown strings.
// See migration table in spec §FIND2-023.
func ValidateRuntimeMode(s string) error {
	switch RuntimeMode(s) {
	case RuntimeGatewayTyped, RuntimeGatewaySDK, RuntimeDirectBrokered, RuntimeDirectClassic, RuntimeGatewayProxy:
		return nil
	}
	if removedRuntimes[s] {
		return fmt.Errorf(
			"runtime %q has been removed (FIND2-023); see migration table at spec §4.2 for replacement: gateway_typed, gateway_sdk, direct_brokered, direct_classic, or gateway_proxy",
			s,
		)
	}
	if plannedRuntimes[s] {
		return fmt.Errorf(
			"runtime %q is not available in this release (planned for 0.2.0); use '--runtime direct_classic' instead",
			s,
		)
	}
	return fmt.Errorf(
		"runtime %q is not a valid runtime mode; valid values: gateway_typed, gateway_sdk, direct_brokered, direct_classic, gateway_proxy",
		s,
	)
}
