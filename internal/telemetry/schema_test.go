package telemetry_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/telemetry"
)

// NOTE: The structs tested here (CLIInvokedEvent, GatewayStartedEvent,
// ConnectionEnrolledEvent, DoctorRunEvent) define the intended v1 wire schema.
// Current production emission via metrics.go uses a flat Event{Name,Fields} approach.
// These tests verify JSON serialisation of the typed schema, not actual emission paths.
// Migration to typed emission is tracked in future cleanup work.

// TestSchema_AllEventsHaveBaseHeader marshals each event type and asserts that
// all BaseEvent fields are present in the output.
func TestSchema_AllEventsHaveBaseHeader(t *testing.T) {
	base := telemetry.BaseEvent{
		EventType: "test_event",
		InstallID: "install-abc123",
		Version:   "1.2.3",
		OS:        "linux",
		Arch:      "amd64",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	requiredKeys := []string{"event_type", "install_id", "version", "os", "arch", "timestamp"}

	assertBaseFields := func(t *testing.T, name string, v any) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: json.Marshal error: %v", name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("%s: json.Unmarshal error: %v", name, err)
		}
		for _, key := range requiredKeys {
			if _, ok := m[key]; !ok {
				t.Errorf("%s: missing base field %q in marshalled output", name, key)
			}
		}
	}

	t.Run("CLIInvokedEvent", func(t *testing.T) {
		ev := telemetry.CLIInvokedEvent{
			BaseEvent:  base,
			Command:    "run",
			Subcommand: "",
			ExitCode:   0,
			DurationMs: 120,
		}
		assertBaseFields(t, "CLIInvokedEvent", ev)

		data, _ := json.Marshal(ev)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		for _, k := range []string{"command", "exit_code", "duration_ms"} {
			if _, ok := m[k]; !ok {
				t.Errorf("CLIInvokedEvent: missing field %q", k)
			}
		}
	})

	t.Run("GatewayStartedEvent", func(t *testing.T) {
		ev := telemetry.GatewayStartedEvent{
			BaseEvent: base,
			Provider:  "aws",
			Runtime:   "local",
		}
		assertBaseFields(t, "GatewayStartedEvent", ev)

		data, _ := json.Marshal(ev)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		for _, k := range []string{"provider", "runtime"} {
			if _, ok := m[k]; !ok {
				t.Errorf("GatewayStartedEvent: missing field %q", k)
			}
		}
	})

	t.Run("ConnectionEnrolledEvent", func(t *testing.T) {
		ev := telemetry.ConnectionEnrolledEvent{
			BaseEvent:   base,
			Provider:    "gcp",
			StorageMode: "reference",
		}
		assertBaseFields(t, "ConnectionEnrolledEvent", ev)

		data, _ := json.Marshal(ev)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		for _, k := range []string{"provider", "storage_mode"} {
			if _, ok := m[k]; !ok {
				t.Errorf("ConnectionEnrolledEvent: missing field %q", k)
			}
		}
	})

	t.Run("DoctorRunEvent", func(t *testing.T) {
		ev := telemetry.DoctorRunEvent{
			BaseEvent:        base,
			Category:         "backend",
			Result:           "fail",
			FailedCheckNames: []string{"check-tls", "check-auth"},
		}
		assertBaseFields(t, "DoctorRunEvent", ev)

		data, _ := json.Marshal(ev)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		for _, k := range []string{"category", "result", "failed_check_names"} {
			if _, ok := m[k]; !ok {
				t.Errorf("DoctorRunEvent: missing field %q", k)
			}
		}
	})

	t.Run("DoctorRunEvent_OmitsFailedChecksWhenEmpty", func(t *testing.T) {
		ev := telemetry.DoctorRunEvent{
			BaseEvent: base,
			Category:  "backend",
			Result:    "ok",
		}
		data, _ := json.Marshal(ev)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		if _, ok := m["failed_check_names"]; ok {
			t.Error("DoctorRunEvent: failed_check_names must be omitted when empty")
		}
	})
}
