// export_test.go — exposes internal symbols for black-box tests in package telemetry_test.
// This file is compiled only during testing (it lives in package telemetry, not telemetry_test).
package telemetry

import (
	"net/http"
	"time"
)

// NewRemoteSinkForTest creates a RemoteSink pointing at the given endpoint with
// shortened retry backoffs suitable for unit tests (50 ms, 100 ms instead of
// production 5 s, 30 s). This avoids multi-minute test waits while still
// exercising the retry logic.
func NewRemoteSinkForTest(endpoint string) *RemoteSink {
	// Temporarily swap the package-level backoffs for the duration of the test.
	// Each test that creates a sink via this constructor will use short backoffs.
	// Production code uses the default retryBackoffs var.
	s := &RemoteSink{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 500 * time.Millisecond},
		backoffs: []time.Duration{50 * time.Millisecond, 100 * time.Millisecond},
	}
	return s
}

// ResolvedTelemetryEndpoint returns the endpoint newRemoteSink() would
// resolve to given the current KEYLATCH_TELEMETRY_URL env var (set via
// t.Setenv in tests). Exposes the https-only validation behavior for testing
// without making newRemoteSink or RemoteSink.endpoint exported.
func ResolvedTelemetryEndpoint() string {
	return newRemoteSink().endpoint
}

// DefaultTelemetryEndpoint exposes defaultTelemetryEndpoint for test assertions.
func DefaultTelemetryEndpoint() string {
	return defaultTelemetryEndpoint
}
