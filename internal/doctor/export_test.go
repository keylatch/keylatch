// export_test.go makes internal check constructors accessible to tests
// in the doctor_test package. Only used during testing.
package doctor

import "github.com/keylatch/keylatch/internal/llmcontext"

// ExportCheckIntegrationMarkers exposes checkIntegrationMarkers for unit tests.
func ExportCheckIntegrationMarkers() Check {
	return checkIntegrationMarkers()
}

// ExportCheckGatewayRunning exposes checkGatewayRunning for unit tests (H11).
func ExportCheckGatewayRunning(env llmcontext.Lookup) Check {
	return checkGatewayRunning(env)
}

// ExportCheckPlaintextRetention exposes checkPlaintextRetention for unit tests (H11).
func ExportCheckPlaintextRetention(env llmcontext.Lookup) Check {
	return checkPlaintextRetention(env)
}

// ExportCheckNoConnections exposes checkNoConnections for unit tests (H11).
func ExportCheckNoConnections(env llmcontext.Lookup) Check {
	return checkNoConnections(env)
}
