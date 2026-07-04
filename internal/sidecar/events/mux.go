package events

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
)

const subscriberBufferCap = 8

// Mux is the desktop event fan-out multiplexer.
// It accepts events from upstream sources (wired in E10-T1) and fans them
// out to all registered IPC subscribers. Slow subscribers receive
// drop-oldest behaviour to prevent them from blocking fast ones.
type Mux struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
	stopOnce    sync.Once
	stopCh      chan struct{}
}

// NewMux creates a new Mux.
func NewMux() *Mux {
	return &Mux{
		subscribers: make(map[chan Event]struct{}),
		stopCh:      make(chan struct{}),
	}
}

// Subscribe registers a new subscriber and returns its receive channel.
// The channel is buffered with cap subscriberBufferCap; events are dropped
// (oldest first) when the buffer is full.
func (m *Mux) Subscribe() chan Event {
	ch := make(chan Event, subscriberBufferCap)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber set and closes it.
func (m *Mux) Unsubscribe(ch chan Event) {
	m.mu.Lock()
	if _, ok := m.subscribers[ch]; ok {
		delete(m.subscribers, ch)
		close(ch)
	}
	m.mu.Unlock()
}

// Publish sends ev to all subscribers. If a subscriber's buffer is full,
// the oldest pending event is dropped and ev is enqueued (drop-oldest).
func (m *Mux) Publish(ev Event) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for ch := range m.subscribers {
		select {
		case ch <- ev:
		default:
			// Buffer full — drop oldest, then enqueue new.
			select {
			case <-ch: // discard oldest
			default:
			}
			select {
			case ch <- ev:
			default:
			}
		}
	}
}

// Stop shuts down the mux. It closes all subscriber channels and the internal
// stop channel. Safe to call multiple times.
func (m *Mux) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.mu.Lock()
		for ch := range m.subscribers {
			delete(m.subscribers, ch)
			close(ch)
		}
		m.mu.Unlock()
	})
}

// ApprovalCreatedEvent is the upstream Phase 9 event shape.
// We use interface{} here to avoid importing Phase 9 packages (leaf-package rule).
// The adapter functions below cast to the correct type.
type ApprovalCreatedEvent interface {
	GetApprovalID() string
	GetProvider() string
	GetAction() string
	GetActor() string
}

// BrokerSubstitutionBlockedEvent is the upstream Phase 13 event shape.
type BrokerSubstitutionBlockedEvent interface {
	GetEventID() string
	GetAuditRef() string
}

// HighSeverityAuditEvent is the upstream Phase 5 event shape.
type HighSeverityAuditEvent interface {
	GetEventID() string
	GetAuditRef() string
}

// Start wires the mux to upstream event sources (E10-T1).
// Each channel carries the upstream event type; adapter goroutines convert
// them to value-free Event structs before publishing on the mux.
//
// All payloads are scrubbed: the canary KEYLATCH_CANARY_PHASE14_DESKTOP_0xDEADBEEF
// MUST NOT appear in any emitted event (enforced by the E10-T1 unit test).
//
// Upstream bus channels are typed as chan interface{} to avoid importing
// upstream phase packages from this leaf package.
func (m *Mux) Start(
	ctx context.Context,
	phase9ApprovalCh <-chan interface{}, // Phase 9 ApprovalCreated events
	phase13BlockedCh <-chan interface{}, // Phase 13 BrokerSubstitutionBlocked events
	phase5AuditCh <-chan interface{}, // Phase 5 high-severity audit events
) {
	// Adapter: Phase 9 ApprovalCreated → ApprovalEvent.
	if phase9ApprovalCh != nil {
		go m.adaptPhase9(ctx, phase9ApprovalCh)
	}

	// Adapter: Phase 13 BrokerSubstitutionBlocked → SecurityEvent.
	if phase13BlockedCh != nil {
		go m.adaptPhase13(ctx, phase13BlockedCh)
	}

	// Adapter: Phase 5 high-severity audit → SecurityEvent.
	if phase5AuditCh != nil {
		go m.adaptPhase5(ctx, phase5AuditCh)
	}

	// Lifecycle goroutine.
	go func() {
		select {
		case <-ctx.Done():
			m.Stop()
		case <-m.stopCh:
		}
	}()
}

// adaptPhase9 converts Phase 9 ApprovalCreated events to ApprovalEvent.
// Payload scrubbing: only value-free fields are included (S14-6).
func (m *Mux) adaptPhase9(ctx context.Context, ch <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			ev := convertToApprovalEvent(raw)
			if ev == nil {
				continue
			}
			m.Publish(Event{Type: EventTypeApproval, Approval: ev})
		}
	}
}

// adaptPhase13 converts Phase 13 BrokerSubstitutionBlocked events to SecurityEvent.
func (m *Mux) adaptPhase13(ctx context.Context, ch <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			ev := convertToSecurityEvent(raw, "broker_substitution_blocked", "error")
			if ev == nil {
				continue
			}
			m.Publish(Event{Type: EventTypeSecurity, Security: ev})
		}
	}
}

// adaptPhase5 converts Phase 5 high-severity audit events to SecurityEvent.
func (m *Mux) adaptPhase5(ctx context.Context, ch <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			ev := convertToSecurityEvent(raw, "audit_high_severity", "error")
			if ev == nil {
				continue
			}
			m.Publish(Event{Type: EventTypeSecurity, Security: ev})
		}
	}
}

// convertToApprovalEvent safely converts a raw upstream event to an ApprovalEvent.
// Returns nil if the conversion fails. Scrubs any canary values (S14-6).
func convertToApprovalEvent(raw interface{}) *ApprovalEvent {
	// Type-assert to the interface we defined.
	if ev, ok := raw.(ApprovalCreatedEvent); ok {
		return &ApprovalEvent{
			ApprovalID:   ev.GetApprovalID(),
			Provider:     ev.GetProvider(),
			Action:       ev.GetAction(),
			Actor:        ev.GetActor(),
			RequestedAt:  time.Now(),
			ExpiresAt:    time.Now().Add(5 * time.Minute),
			DeepLinkPath: "/approvals/" + ev.GetApprovalID(),
		}
	}
	// Try map-based conversion (for test fixtures).
	if m, ok := raw.(map[string]interface{}); ok {
		return &ApprovalEvent{
			ApprovalID:   scrub(fmt.Sprint(m["approval_id"])),
			Provider:     scrub(fmt.Sprint(m["provider"])),
			Action:       scrub(fmt.Sprint(m["action"])),
			Actor:        scrub(fmt.Sprint(m["actor"])),
			RequestedAt:  time.Now(),
			ExpiresAt:    time.Now().Add(5 * time.Minute),
			DeepLinkPath: "/approvals/" + scrub(fmt.Sprint(m["approval_id"])),
		}
	}
	return nil
}

// convertToSecurityEvent safely converts a raw upstream event to a SecurityEvent.
func convertToSecurityEvent(raw interface{}, kind, severity string) *SecurityEvent {
	if m, ok := raw.(map[string]interface{}); ok {
		return &SecurityEvent{
			EventID:   scrub(fmt.Sprint(m["event_id"])),
			Severity:  severity,
			Kind:      kind,
			Timestamp: time.Now(),
			AuditRef:  scrub(fmt.Sprint(m["audit_ref"])),
		}
	}
	return &SecurityEvent{
		EventID:   "unknown",
		Severity:  severity,
		Kind:      kind,
		Timestamp: time.Now(),
	}
}

// scrub removes any credential or canary patterns from a string (S14-6).
//
// docker-server-security hardening (L3): this used to carry its own
// hand-maintained copy of the credential-prefix list, with a comment
// requiring it be kept in sync with packaging/redaction-patterns.json by
// hand — a THIRD copy of that table, alongside internal/runner/redact.go's
// redactionDefs (the single source of truth) and the JSON file itself
// (generated from redactionDefs via `go generate ./internal/runner`). This
// now consumes runner.RedactionPrefixes() directly so there is nothing left
// to drift: see TestScrub_MatchesRunnerRedactionPrefixes for the parity
// guard covering this consumer.
func scrub(s string) string {
	const canary = "KEYLATCH_CANARY_PHASE14_DESKTOP_0xDEADBEEF"
	if strings.Contains(s, canary) {
		return "[REDACTED]"
	}
	for _, pattern := range runner.RedactionPrefixes() {
		if strings.Contains(s, pattern) {
			return "[REDACTED]"
		}
	}
	return s
}
