package telemetry_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
)

// No hosted feature is active and no background opt-in exists in the
// release artifact. Nothing in production ever constructs a real Sink (New is
// only called from this package's own tests) or wires a non-nil
// gateway.Server.TelemetrySink, so RemoteSink/LocalFileSink emission is
// already unreachable; this test pins that containment via the manifest so
// a future wiring change is caught here.
func TestSecurityRegression_HostedTelemetryUnavailable(t *testing.T) {
	if manifest.Current().Enabled("hosted_telemetry") {
		t.Fatal("hosted_telemetry is Supported — telemetry.New(\"remote\", ...) would become reachable")
	}
	if manifest.Current().Enabled("receipt_sharing") {
		t.Fatal("receipt_sharing is Supported")
	}
}
