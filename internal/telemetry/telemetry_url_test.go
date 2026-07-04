package telemetry_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/telemetry"
	"github.com/stretchr/testify/assert"
)

// TestNewRemoteSink_RejectsNonHTTPSOverride verifies M-input-validation:
// KEYLATCH_TELEMETRY_URL must use https — a plaintext http override is
// silently rejected in favor of the hardcoded production endpoint.
func TestNewRemoteSink_RejectsNonHTTPSOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_URL", "http://127.0.0.1:9999/mock")
	got := telemetry.ResolvedTelemetryEndpoint()
	assert.Equal(t, telemetry.DefaultTelemetryEndpoint(), got)
}

// TestNewRemoteSink_AcceptsHTTPSOverride verifies a well-formed https
// override is honored.
func TestNewRemoteSink_AcceptsHTTPSOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_URL", "https://mock.example.com/v1/events")
	got := telemetry.ResolvedTelemetryEndpoint()
	assert.Equal(t, "https://mock.example.com/v1/events", got)
}

// TestNewRemoteSink_RejectsMalformedOverride verifies a syntactically
// malformed override falls back to the default endpoint rather than
// producing a broken *http.Client target.
func TestNewRemoteSink_RejectsMalformedOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_URL", "://not-a-url")
	got := telemetry.ResolvedTelemetryEndpoint()
	assert.Equal(t, telemetry.DefaultTelemetryEndpoint(), got)
}

// TestNewRemoteSink_NoOverride verifies the default endpoint is used when
// KEYLATCH_TELEMETRY_URL is unset.
func TestNewRemoteSink_NoOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_URL", "")
	got := telemetry.ResolvedTelemetryEndpoint()
	assert.Equal(t, telemetry.DefaultTelemetryEndpoint(), got)
}
