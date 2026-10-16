// Package policy implements the keylatch policy engine.
// runtime_enum.go defines the closed set of valid runtime modes and
// provides a parser that rejects removed or unknown names.
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
	// RuntimePlaceholder is tier D3: the child holds placeholders the daemon's
	// proxy replaces. RuntimeContained is tier D5: the child holds the real
	// value inside the Keylatch sandbox.
	RuntimePlaceholder RuntimeMode = "placeholder"
	RuntimeContained   RuntimeMode = "contained"
)

// removedRuntimes is the set of names that have been removed.
// ValidateRuntimeMode returns a descriptive error pointing to the migration table.
var removedRuntimes = map[string]bool{
	"direct_run":     true,
	"local_gateway":  true,
	"hosted_gateway": true,
}

// ValidateRuntimeMode returns nil for a valid runtime mode.
// It returns a descriptive error for removed names and unknown strings.
// See migration table in spec §.
func ValidateRuntimeMode(s string) error {
	switch RuntimeMode(s) {
	case RuntimeGatewayTyped, RuntimeGatewaySDK, RuntimeDirectBrokered, RuntimeDirectClassic, RuntimeGatewayProxy, RuntimePlaceholder, RuntimeContained:
		return nil
	}
	if removedRuntimes[s] {
		return fmt.Errorf(
			"runtime %q has been removed; see migration table at spec §4.2 for replacement: gateway_typed, gateway_sdk, direct_brokered, direct_classic, or gateway_proxy",
			s,
		)
	}
	return fmt.Errorf(
		"runtime %q is not a valid runtime mode; valid values: gateway_typed, gateway_sdk, direct_brokered, direct_classic, gateway_proxy",
		s,
	)
}
