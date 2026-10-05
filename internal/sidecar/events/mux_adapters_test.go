package events_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/sidecar/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type gdApproval struct{ id, provider, action, actor string }

func (a gdApproval) GetApprovalID() string { return a.id }
func (a gdApproval) GetProvider() string   { return a.provider }
func (a gdApproval) GetAction() string     { return a.action }
func (a gdApproval) GetActor() string      { return a.actor }

func gdRecv(t *testing.T, ch <-chan events.Event) events.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		require.True(t, ok, "subscriber channel closed unexpectedly")
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event")
		return events.Event{}
	}
}

func gdWaitClosed(t *testing.T, ch <-chan events.Event) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("subscriber channel was not closed")
		}
	}
}

func gdFakeSecret() string {
	return runner.RedactionPrefixes()[0] + strings.Repeat("Q", 32)
}

func TestMuxStart_ApprovalAdapter(t *testing.T) {
	mux := events.NewMux()
	sub := mux.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	approvals := make(chan interface{})
	mux.Start(ctx, approvals, nil, nil)

	approvals <- 42
	approvals <- gdApproval{id: "ap-1", provider: "github", action: "read:repo", actor: "codex"}
	before := time.Now()
	approvals <- map[string]interface{}{"approval_id": "ap-2", "provider": "openai", "action": "chat", "actor": gdFakeSecret()}

	first := gdRecv(t, sub)
	assert.Equal(t, events.EventTypeApproval, first.Type, "unconvertible upstream values must be skipped")
	require.NotNil(t, first.Approval)
	assert.Equal(t, "ap-1", first.Approval.ApprovalID)
	assert.Equal(t, "github", first.Approval.Provider)
	assert.Equal(t, "read:repo", first.Approval.Action)
	assert.Equal(t, "codex", first.Approval.Actor)
	assert.Equal(t, "/approvals/ap-1", first.Approval.DeepLinkPath)
	assert.InDelta(t, float64(5*time.Minute), float64(first.Approval.ExpiresAt.Sub(first.Approval.RequestedAt)), float64(time.Second))

	second := gdRecv(t, sub)
	require.NotNil(t, second.Approval)
	assert.Equal(t, "ap-2", second.Approval.ApprovalID)
	assert.Equal(t, "[REDACTED]", second.Approval.Actor, "credential-shaped values must be scrubbed")
	assert.Equal(t, "/approvals/ap-2", second.Approval.DeepLinkPath)
	assert.False(t, second.Approval.RequestedAt.Before(before.Add(-time.Second)))
	assert.Nil(t, second.Security)
	assert.Nil(t, second.Receipt)
}

func TestMuxStart_SecurityAdapters(t *testing.T) {
	mux := events.NewMux()
	sub := mux.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := make(chan interface{})
	audit := make(chan interface{})
	mux.Start(ctx, nil, broker, audit)

	broker <- map[string]interface{}{"event_id": "ev-1", "audit_ref": "ar-1"}
	ev := gdRecv(t, sub)
	assert.Equal(t, events.EventTypeSecurity, ev.Type)
	require.NotNil(t, ev.Security)
	assert.Equal(t, "ev-1", ev.Security.EventID)
	assert.Equal(t, "ar-1", ev.Security.AuditRef)
	assert.Equal(t, "broker_substitution_blocked", ev.Security.Kind)
	assert.Equal(t, "error", ev.Security.Severity)
	assert.False(t, ev.Security.Timestamp.IsZero())

	broker <- "opaque upstream value"
	ev = gdRecv(t, sub)
	require.NotNil(t, ev.Security)
	assert.Equal(t, "unknown", ev.Security.EventID, "non-map payloads must not be echoed")
	assert.Empty(t, ev.Security.AuditRef)

	secret := gdFakeSecret()
	audit <- map[string]interface{}{"event_id": secret, "audit_ref": "x " + secret}
	ev = gdRecv(t, sub)
	require.NotNil(t, ev.Security)
	assert.Equal(t, "audit_high_severity", ev.Security.Kind)
	assert.Equal(t, "[REDACTED]", ev.Security.EventID)
	assert.Equal(t, "[REDACTED]", ev.Security.AuditRef)

	audit <- 3.14
	ev = gdRecv(t, sub)
	require.NotNil(t, ev.Security)
	assert.Equal(t, "unknown", ev.Security.EventID)
	assert.Equal(t, "audit_high_severity", ev.Security.Kind)
}

func TestMuxStart_ContextCancelStopsMux(t *testing.T) {
	mux := events.NewMux()
	sub := mux.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())

	mux.Start(ctx, make(chan interface{}), make(chan interface{}), make(chan interface{}))
	cancel()
	gdWaitClosed(t, sub)

	mux.Stop()
	mux.Publish(events.Event{Type: events.EventTypeReceipt})
}

func TestMuxStart_StopEndsAdapters(t *testing.T) {
	mux := events.NewMux()
	sub := mux.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	approvals := make(chan interface{})
	broker := make(chan interface{})
	audit := make(chan interface{})
	mux.Start(ctx, approvals, broker, audit)
	mux.Stop()
	gdWaitClosed(t, sub)

	assert.NotPanics(t, func() { mux.Publish(events.Event{Type: events.EventTypeReceipt}) },
		"publishing after Stop must not write to closed subscriber channels")
}

func TestMuxStart_ClosedUpstreamChannels(t *testing.T) {
	mux := events.NewMux()
	sub := mux.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	approvals := make(chan interface{})
	broker := make(chan interface{})
	audit := make(chan interface{})
	close(approvals)
	close(broker)
	close(audit)
	mux.Start(ctx, approvals, broker, audit)

	select {
	case ev, ok := <-sub:
		t.Fatalf("no event expected from closed upstreams, got %+v (open=%v)", ev, ok)
	case <-time.After(100 * time.Millisecond):
	}

	mux.Publish(events.Event{Type: events.EventTypeReceipt, Receipt: &events.ReceiptEvent{ReceiptID: "r"}})
	assert.Equal(t, "r", gdRecv(t, sub).Receipt.ReceiptID, "mux keeps working after upstreams close")
}

func TestMuxUnsubscribe_UnknownChannelIsNoop(t *testing.T) {
	mux := events.NewMux()
	foreign := make(chan events.Event, 1)
	mux.Unsubscribe(foreign)
	foreign <- events.Event{}
	assert.Len(t, foreign, 1, "foreign channel must not be closed")

	sub := mux.Subscribe()
	mux.Unsubscribe(sub)
	mux.Unsubscribe(sub)
	_, ok := <-sub
	assert.False(t, ok)
}
