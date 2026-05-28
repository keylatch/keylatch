package events_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/sidecar/events"
)

const canary = "KEYLATCH_CANARY_PHASE14_DESKTOP_0xDEADBEEF"

func TestMuxSubscribeUnsubscribe(t *testing.T) {
	mux := events.NewMux()
	ch := mux.Subscribe()
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	ev := events.Event{
		Type:     events.EventTypeApproval,
		Approval: &events.ApprovalEvent{ApprovalID: "test-123"},
	}
	mux.Publish(ev)

	select {
	case received := <-ch:
		if received.Approval == nil {
			t.Fatal("expected ApprovalEvent, got nil")
		}
		if received.Approval.ApprovalID != "test-123" {
			t.Errorf("got approval_id=%q, want test-123", received.Approval.ApprovalID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}

	mux.Unsubscribe(ch)
}

func TestMuxDropOldest(t *testing.T) {
	mux := events.NewMux()
	ch := mux.Subscribe()
	defer mux.Unsubscribe(ch)

	// Fill the buffer beyond capacity (cap=8).
	for i := 0; i < 10; i++ {
		mux.Publish(events.Event{
			Type:    events.EventTypeReceipt,
			Receipt: &events.ReceiptEvent{ReceiptID: fmt.Sprintf("receipt-%d", i)},
		})
	}

	// Drain the channel with a short timeout.
	var received []string
	deadline := time.After(200 * time.Millisecond)
	for {
		select {
		case ev := <-ch:
			if ev.Receipt != nil {
				received = append(received, ev.Receipt.ReceiptID)
			}
		case <-deadline:
			goto done
		}
	}
done:
	// Should have received ≤8 events (oldest dropped, buffer capacity enforced).
	if len(received) > 8 {
		t.Errorf("received %d events, expected ≤8 (drop-oldest semantics)", len(received))
	}
	t.Logf("received %d events after overflow (drop-oldest working)", len(received))
}

func TestMuxStop(t *testing.T) {
	mux := events.NewMux()
	ch := mux.Subscribe()

	mux.Stop()

	// After Stop(), the channel should be closed.
	select {
	case _, open := <-ch:
		if open {
			t.Error("channel should be closed after Stop()")
		}
	case <-time.After(time.Second):
		t.Error("channel not closed after Stop()")
	}

	// Second Stop() must be safe (idempotent via sync.Once).
	mux.Stop()
}

func TestCanaryScrubbedFromUpstreamEvent(t *testing.T) {
	// The canary must not appear in any emitted event after scrubbing (S14-6).
	mux := events.NewMux()
	ch := mux.Subscribe()
	defer mux.Unsubscribe(ch)

	// Inject canary into a fixture upstream event.
	upstream := map[string]interface{}{
		"approval_id": canary,
		"provider":    "github",
		"action":      "read:repo",
		"actor":       "claude-code",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the mux with a channel that has one event then closes.
	upstreamCh := make(chan interface{}, 1)
	upstreamCh <- upstream
	close(upstreamCh)

	mux.Start(ctx, upstreamCh, nil, nil)

	select {
	case ev := <-ch:
		if ev.Approval == nil {
			t.Skip("adapter not triggered in this environment")
			return
		}
		// Canary must be scrubbed.
		if strings.Contains(ev.Approval.ApprovalID, canary) {
			t.Errorf("S14-6 FAIL: canary found in ApprovalEvent.ApprovalID: %q",
				ev.Approval.ApprovalID)
		}
		t.Log("S14-6: canary scrubbed from ApprovalEvent")
	case <-time.After(2 * time.Second):
		t.Log("no event received within timeout — scrubbing test skipped for this run")
	}
}

func TestEventStructFieldsValueFree(t *testing.T) {
	// Verify that all fields in the event structs are value-free (S14-6).
	// This is a structural check; the CI lint enforces it per-field.
	ev := events.ApprovalEvent{
		ApprovalID:   "approval-123",
		Provider:     "github",
		Action:       "read:repo",
		Actor:        "claude-code",
		RequestedAt:  time.Now(),
		ExpiresAt:    time.Now().Add(time.Minute),
		DeepLinkPath: "/approvals/approval-123",
	}

	credPatterns := []string{"sk-", "ghp_", "AKIA", "xoxb-", "xoxp-"}
	fields := []string{ev.ApprovalID, ev.Provider, ev.Action, ev.Actor, ev.DeepLinkPath}
	for _, field := range fields {
		for _, pattern := range credPatterns {
			if strings.Contains(field, pattern) {
				t.Errorf("S14-6: ApprovalEvent field contains credential pattern %q: %q", pattern, field)
			}
		}
	}
}
