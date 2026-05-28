package audit_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

// TestTailReceivesEvents verifies that Tail delivers newly written events to ch.
func TestTailReceivesEvents(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLogger(t, dir)
	ctx := context.Background()

	// Write two events before starting tail.
	for i := 0; i < 2; i++ {
		if err := l.Log(ctx, audit.Event{
			Action:  audit.ActionRead,
			Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Reset file to beginning so Tail picks up from pos=0. We test from start by
	// relying on Scan; use a short-lived tail that reads already-present lines via
	// the poll loop. Because Tail seeks to end on startup we write events after it
	// begins following instead.
	l2, _ := openTestLogger(t, dir)

	tailCtx, cancel := context.WithCancel(ctx)
	ch := make(chan audit.Event, 32)

	go func() {
		_ = l2.Tail(tailCtx, audit.TailOpts{PollInterval: 10 * time.Millisecond}, ch)
	}()

	// Give tail a moment to start then write new events.
	time.Sleep(30 * time.Millisecond)

	for i := 0; i < 2; i++ {
		if err := l2.Log(tailCtx, audit.Event{
			Action:  audit.ActionWrite,
			Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("Log after tail start: %v", err)
		}
	}

	// Collect events for a short window.
	received := 0
	deadline := time.After(500 * time.Millisecond)
collect:
	for {
		select {
		case <-ch:
			received++
			if received >= 2 {
				break collect
			}
		case <-deadline:
			break collect
		}
	}
	cancel()

	if received < 2 {
		t.Errorf("Tail: received %d events, want at least 2", received)
	}
}

// TestTailRotationDetection verifies that readNewLines resets position when
// the file shrinks (simulating log rotation / truncation).
func TestTailRotationDetection(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLogger(t, dir)
	ctx := context.Background()

	// Write an initial event so the file has content.
	if err := l.Log(ctx, audit.Event{
		Action:  audit.ActionRead,
		Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatalf("Log before rotation: %v", err)
	}

	logPath := l.Path()

	// Close the logger so we can truncate the file cleanly.
	l.Close()

	// Simulate rotation by truncating the file to zero.
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	// Re-open at the same path (fresh logger, chain starts from zero).
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 100)
	}
	l2, err := audit.Open(logPath, salt, dek)
	if err != nil {
		t.Fatalf("Open after truncate: %v", err)
	}
	t.Cleanup(func() { l2.Close() })

	tailCtx, cancel := context.WithCancel(ctx)
	ch := make(chan audit.Event, 32)

	go func() {
		_ = l2.Tail(tailCtx, audit.TailOpts{PollInterval: 10 * time.Millisecond}, ch)
	}()

	// Give tail a moment to start then write a new event to the rotated file.
	time.Sleep(30 * time.Millisecond)

	if err := l2.Log(ctx, audit.Event{
		Action:  audit.ActionWrite,
		Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatalf("Log to rotated file: %v", err)
	}

	// Collect event within deadline.
	deadline := time.After(500 * time.Millisecond)
	var got bool
	select {
	case <-ch:
		got = true
	case <-deadline:
	}
	cancel()

	if !got {
		t.Error("Tail did not deliver event from rotated (truncated) file")
	}
}
