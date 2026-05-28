package telemetry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	klruntime "github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/telemetry"
)

// TestSink_KillSwitchOverridesEverything verifies that KEYLATCH_TELEMETRY_DISABLE=1
// causes ShouldEmit to return false even when TelemetryEnabled is true.
func TestSink_KillSwitchOverridesEverything(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_DISABLE", "1")

	settings := klruntime.EffectiveSettings{TelemetryEnabled: true}
	if telemetry.ShouldEmit(settings) {
		t.Error("ShouldEmit must return false when KEYLATCH_TELEMETRY_DISABLE=1")
	}
}

// TestSink_KillSwitchAcceptsTrueVariants verifies that KEYLATCH_TELEMETRY_DISABLE
// accepts "true" and "TRUE" in addition to "1".
func TestSink_KillSwitchAcceptsTrueVariants(t *testing.T) {
	settings := klruntime.EffectiveSettings{TelemetryEnabled: true}

	for _, v := range []string{"true", "TRUE", "True"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("KEYLATCH_TELEMETRY_DISABLE", v)
			if telemetry.ShouldEmit(settings) {
				t.Errorf("ShouldEmit must return false when KEYLATCH_TELEMETRY_DISABLE=%q", v)
			}
		})
	}
}

// TestSink_KillSwitchAbsent verifies that without the kill-switch,
// ShouldEmit honours TelemetryEnabled normally.
func TestSink_KillSwitchAbsent(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_DISABLE", "")

	enabled := klruntime.EffectiveSettings{TelemetryEnabled: true}
	if !telemetry.ShouldEmit(enabled) {
		t.Error("ShouldEmit should return true when TelemetryEnabled=true and kill-switch is absent")
	}

	disabled := klruntime.EffectiveSettings{TelemetryEnabled: false}
	if telemetry.ShouldEmit(disabled) {
		t.Error("ShouldEmit should return false when TelemetryEnabled=false")
	}
}

// TestSink_OnlyEmitsInTelemetryMode verifies that ShouldEmit is false in
// standard and canary modes (where TelemetryEnabled is false).
func TestSink_OnlyEmitsInTelemetryMode(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_DISABLE", "")

	cases := []struct {
		mode klruntime.OperatingMode
		want bool
	}{
		{klruntime.ModeStandard, false},
		{klruntime.ModeTelemetry, true},
		{klruntime.ModeCanary, false},
	}

	for _, tc := range cases {
		settings := klruntime.EffectiveSettingsForMode(tc.mode, nil)
		got := telemetry.ShouldEmit(settings)
		if got != tc.want {
			t.Errorf("mode=%s: ShouldEmit=%v, want %v", tc.mode, got, tc.want)
		}
	}
}

// TestSink_CustomModeReadsCustomTelemetryFlag verifies that in ModeCustom,
// ShouldEmit respects the CustomModeConfig.TelemetryEnabled flag.
func TestSink_CustomModeReadsCustomTelemetryFlag(t *testing.T) {
	t.Setenv("KEYLATCH_TELEMETRY_DISABLE", "")

	withTelemetry := &klruntime.CustomModeConfig{TelemetryEnabled: true}
	settings := klruntime.EffectiveSettingsForMode(klruntime.ModeCustom, withTelemetry)
	if !telemetry.ShouldEmit(settings) {
		t.Error("custom mode with TelemetryEnabled=true: ShouldEmit must return true")
	}

	withoutTelemetry := &klruntime.CustomModeConfig{TelemetryEnabled: false}
	settings2 := klruntime.EffectiveSettingsForMode(klruntime.ModeCustom, withoutTelemetry)
	if telemetry.ShouldEmit(settings2) {
		t.Error("custom mode with TelemetryEnabled=false: ShouldEmit must return false")
	}

	// nil custom config → all false
	settings3 := klruntime.EffectiveSettingsForMode(klruntime.ModeCustom, nil)
	if telemetry.ShouldEmit(settings3) {
		t.Error("custom mode with nil config: ShouldEmit must return false")
	}
}

// TestSink_RetriesWithBackoff verifies that the RemoteSink retries on failure.
// The mock server fails on the first two attempts and succeeds on the third.
func TestSink_RetriesWithBackoff(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		_, _ = io.ReadAll(r.Body)
		if n < 3 {
			// Simulate a transient server error.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := telemetry.NewRemoteSinkForTest(srv.URL)
	ctx := context.Background()
	sink.Emit(ctx, telemetry.Event{Name: "test_retry"})

	// Wait enough time for 3 attempts with backoffs (5s + 30s = 35s wall-clock max).
	// In the test we use shortened backoffs via NewRemoteSinkForTest — see impl.
	// We give 5 seconds as the test uses injected short backoffs.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got := attempts.Load()
	if got < 3 {
		t.Errorf("expected at least 3 attempts (retry behaviour), got %d", got)
	}
}

// TestSink_SilentlyFailsAfterMaxAttempts verifies that a sink that always fails
// eventually gives up without panicking or blocking the test.
func TestSink_SilentlyFailsAfterMaxAttempts(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := telemetry.NewRemoteSinkForTest(srv.URL)
	ctx := context.Background()
	sink.Emit(ctx, telemetry.Event{Name: "test_max_retries"})

	// Allow enough time for all attempts.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The sink must not make more than 3 attempts.
	time.Sleep(200 * time.Millisecond) // small buffer to catch extra calls
	got := attempts.Load()
	if got > 3 {
		t.Errorf("RemoteSink made %d attempts, expected at most 3", got)
	}
	// No panic reaching here = silent failure confirmed.
}
