package runtime_test

// runtime_schema_test.go
//
// TestRuntimeSchemaConsistency asserts that the schema-declarable modes
// (those accepted in provider template YAML files) are exactly the set present
// in the registry's valid-modes enumeration, and that direct_classic is
// intentionally absent from that set.
//
// Note: direct_classic_sandboxed has been reinstated as a new sibling
// mode. It is NOT schema-declarable (providers do not declare it in YAML) but it
// IS present in runtime.AllModes so the runtime layer can route it. This is
// distinct from direct_classic which remains permanently removed.
//
// This test FAILS if someone re-adds direct_classic to the registry enum.
// It was scaffolded in P0 and went green in P1 wave 1
// when direct_classic was removed from AllModes.

import (
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// schemaDeclarableModes is the set of modes that may appear in provider
// template YAML files. direct_classic must not be here.
// direct_classic_sandboxed is a CLI-only mode and is also not schema-declarable.
var schemaDeclarableModes = []registry.RuntimeMode{
	registry.RuntimeGatewayTyped,
	registry.RuntimeGatewaySDK,
	registry.RuntimeDirectBrokered,
	registry.RuntimeGatewayProxy,
}

// TestRuntimeSchemaConsistency verifies that the schema-declarable modes
// do not include removed or CLI-only modes.
func TestRuntimeSchemaConsistency(t *testing.T) {
	// Verify the expected schema set is valid in the registry.
	for _, m := range schemaDeclarableModes {
		if !registry.IsValidRuntimeMode(m) {
			t.Errorf("mode %q is in schemaDeclarableModes but not valid in registry", m)
		}
	}

	// direct_classic must NOT be schema-declarable — it was permanently removed.
	// direct_classic_sandboxed is a CLI-only mode and must not be schema-declarable.
	forbiddenInSchema := []string{"direct_classic", "direct_classic_sandboxed"}
	for _, forbidden := range forbiddenInSchema {
		if registry.IsValidRuntimeMode(registry.RuntimeMode(forbidden)) {
			t.Errorf("mode %q must not be schema-declarable — it is removed or CLI-only", forbidden)
		}
	}

	// AllModes must not contain direct_classic (permanently removed).
	// direct_classic_sandboxed IS allowed in AllModes (reinstated).
	for _, m := range runtime.AllModes {
		if string(m) == "direct_classic" {
			t.Errorf("runtime.AllModes still contains permanently removed mode %q", m)
		}
	}

	// Verify direct_classic_sandboxed IS present in AllModes.
	found := false
	for _, m := range runtime.AllModes {
		if m == runtime.RuntimeDirectClassicSandboxed {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("runtime.AllModes must contain RuntimeDirectClassicSandboxed")
	}
}
