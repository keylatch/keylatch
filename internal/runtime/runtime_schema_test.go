package runtime_test

// runtime_schema_test.go
//
// TestRuntimeSchemaConsistency asserts that the schema-declarable modes
// (those accepted in provider template YAML files) are exactly the set present
// in the registry's valid-modes enumeration, and that direct_classic is
// intentionally absent from that set.
//
// This test FAILS if someone re-adds direct_classic or
// direct_classic_sandboxed to the registry enum or to runtime.AllModes.

import (
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// schemaDeclarableModes is the set of modes that may appear in provider
// template YAML files. The removed classic modes must not be here.
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

	forbidden := []string{"direct_classic", "direct_classic_sandboxed"}
	for _, f := range forbidden {
		if registry.IsValidRuntimeMode(registry.RuntimeMode(f)) {
			t.Errorf("mode %q must not be schema-declarable — it was removed", f)
		}
		for _, m := range runtime.AllModes {
			if string(m) == f {
				t.Errorf("runtime.AllModes still contains removed mode %q", m)
			}
		}
	}
}
