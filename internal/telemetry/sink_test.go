package telemetry_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/telemetry"
)

func TestNoopSink(t *testing.T) {
	s := telemetry.NoopSink{}
	// Must not panic.
	s.Emit(context.Background(), telemetry.Event{Name: "test"})
}

func TestLocalFileSink(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "telemetry-*.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	s := telemetry.LocalFileSink{Path: f.Name()}
	s.Emit(context.Background(), telemetry.Event{
		Name:   "setup_completed",
		Fields: map[string]string{"backend": "keychain"},
	})

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "setup_completed") {
		t.Errorf("expected setup_completed in output, got: %s", data)
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "key=") {
		t.Errorf("telemetry output must not contain credential bytes")
	}
}
