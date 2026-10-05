package telemetry_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
)

// F21: no hosted feature is active and no background opt-in exists in the
// M1 artifact. Nothing in production ever constructs a real Sink (New is
// only called from this package's own tests) or wires a non-nil
// gateway.Server.TelemetrySink, so RemoteSink/LocalFileSink emission is
// already unreachable; this test pins that containment via the manifest so
// a future wiring change is caught here.
func TestSecurityRegression_F21_HostedTelemetryUnavailableInM1(t *testing.T) {
	if manifest.Current().Enabled("hosted_telemetry") {
		t.Fatal("hosted_telemetry is Supported in M1 — telemetry.New(\"remote\", ...) would become reachable")
	}
	if manifest.Current().Enabled("receipt_sharing") {
		t.Fatal("receipt_sharing is Supported in M1")
	}
}
