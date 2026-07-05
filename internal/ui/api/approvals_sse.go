// Package api — admin SSE approval inbox.
//
// Security invariants:
// - All SSE payloads are value-free: requester is HMACd, never raw email/ID.
// - Emit within 1s of approval state change (buffered channel, non-blocking).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/approval"
)

// ApprovalSSEEvent is the value-free SSE payload for an approval inbox event.
// All sensitive values (requester) are HMACd.
type ApprovalSSEEvent struct {
	ApprovalID    string `json:"approval_id"`
	Capability    string `json:"capability"`
	Connection    string `json:"connection"`
	RequesterHMAC string `json:"requester_hmac"` // HMACd — value-free invariant
	Status        string `json:"status"`
	ExpiresAt     string `json:"expires_at"` // RFC3339
}

// ApprovalBus is a simple pub/sub bus for approval events.
// Subscribers receive events within 1s of state change.
type ApprovalBus struct {
	mu   sync.Mutex
	subs []chan ApprovalSSEEvent
}

// globalApprovalBus is the process-wide approval event bus.
var globalApprovalBus = &ApprovalBus{}

// Subscribe returns a channel that receives approval events.
// The channel is buffered (capacity 8) to ensure emit within 1s.
// Caller must call Unsubscribe when done.
func (b *ApprovalBus) Subscribe() chan ApprovalSSEEvent {
	ch := make(chan ApprovalSSEEvent, 8)
	b.mu.Lock()
	b.subs = append(b.subs, ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber list and closes it.
func (b *ApprovalBus) Unsubscribe(ch chan ApprovalSSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, s := range b.subs {
		if s == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Publish sends an event to all current subscribers non-blocking.
// Subscribers with full buffers are skipped (never blocks local ops).
func (b *ApprovalBus) Publish(ev ApprovalSSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- ev:
		default:
			// subscriber's buffer full — drop (non-blocking).
		}
	}
}

// PublishApproval converts an ApprovalRequest to a value-free SSE event
// and publishes it on the global bus.
func PublishApproval(req *approval.ApprovalRequest) {
	PublishApprovalOnBus(globalApprovalBus, req)
}

// PublishApprovalOnBus publishes req to the given bus.
// Exported for use in tests that provide a custom bus.
func PublishApprovalOnBus(bus *ApprovalBus, req *approval.ApprovalRequest) {
	ev := ApprovalSSEEvent{
		ApprovalID:    req.ID,
		Capability:    req.Capability,
		Connection:    req.Connection,
		RequesterHMAC: req.RequesterHMAC, // already HMACd in approval.Create
		Status:        string(req.Status),
		ExpiresAt:     req.ExpiresAt.UTC().Format(time.RFC3339),
	}
	bus.Publish(ev)
}

// AdminApprovalsSSEHandler handles GET /admin/approvals/stream (SSE inbox).
//
// Security: caller must have already passed the admin role gate and CSRF
// check in AdminHandler.ServeHTTP before reaching this handler.
// All emitted payloads are value-free (RequesterHMAC never contains raw IDs).
type AdminApprovalsSSEHandler struct {
	Team *team.Team
	Bus  *ApprovalBus // defaults to globalApprovalBus if nil
}

// ServeHTTP streams approval events as SSE.
// Emits an initial heartbeat immediately, then streams events within 1s of
// state change via the ApprovalBus, until the client disconnects.
func (h *AdminApprovalsSSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Initial heartbeat — emitted immediately (well within 1s).
	h.writeSSEEvent(w, "heartbeat", map[string]string{
		"time": time.Now().UTC().Format(time.RFC3339),
	})
	flusher.Flush()

	bus := h.Bus
	if bus == nil {
		bus = globalApprovalBus
	}

	ch := bus.Subscribe()
	defer bus.Unsubscribe(ch)

	// Heartbeat ticker keeps the connection alive over idle periods.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			// Client disconnected — clean shutdown.
			return

		case ev, ok := <-ch:
			if !ok {
				return
			}
			h.writeSSEEvent(w, "approval", ev)
			flusher.Flush()

		case <-ticker.C:
			h.writeSSEEvent(w, "heartbeat", map[string]string{
				"time": time.Now().UTC().Format(time.RFC3339),
			})
			flusher.Flush()
		}
	}
}

// writeSSEEvent writes a single SSE event to w.
// Each event line is "data: <json>\n\n" prefixed by "event: <name>\n".
func (h *AdminApprovalsSSEHandler) writeSSEEvent(w http.ResponseWriter, event string, data interface{}) {
	b, err := json.Marshal(data)
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: {\"error\":\"marshal\"}\n\n")
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
}
