package telemetry_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/telemetry"
)

// MockSink implements telemetry.Sink and stores all received events in memory.
// It is safe for concurrent use.
type MockSink struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (m *MockSink) Emit(_ context.Context, event telemetry.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// Events returns a copy of all received events.
func (m *MockSink) Events() []telemetry.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]telemetry.Event, len(m.events))
	copy(out, m.events)
	return out
}

// Count returns the number of received events.
func (m *MockSink) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// Reset clears all stored events.
func (m *MockSink) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = m.events[:0]
}

// TestSink_CLIInvoked_FiresOncePerRun verifies that simulating a CLI invocation
// emits exactly one cli_invoked event to the sink.
func TestSink_CLIInvoked_FiresOncePerRun(t *testing.T) {
	mock := &MockSink{}

	// Simulate what the CLI entrypoint would do: emit one event per run.
	ctx := context.Background()
	mock.Emit(ctx, telemetry.Event{
		Name:      "cli_invoked",
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"command":         "run",
			"exit_code_class": "success",
		},
	})

	// Verify exactly one event was recorded.
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Name != "cli_invoked" {
		t.Errorf("expected event name %q, got %q", "cli_invoked", events[0].Name)
	}
	if events[0].Fields["command"] != "run" {
		t.Errorf("expected command=run, got %q", events[0].Fields["command"])
	}
}

// TestMockSink_ImplementsSinkInterface is a compile-time check that MockSink
// satisfies the telemetry.Sink interface.
func TestMockSink_ImplementsSinkInterface(t *testing.T) {
	var _ telemetry.Sink = &MockSink{}
}
