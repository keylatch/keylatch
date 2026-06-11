// Package api — RuntimeReceipt ring buffer and HTTP handlers for /v1/receipts.
//
// ReceiptStore holds the last N RuntimeReceipts in memory. The store is nil-safe
// on every read path; nil means "no receipts available" and returns empty arrays.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
)

// ReceiptStore is a thread-safe in-memory ring buffer of RuntimeReceipts.
// It notifies registered subscribers on every Push.
type ReceiptStore struct {
	mu      sync.RWMutex
	entries []runner.RuntimeReceipt
	cap     int
	subs    []chan runner.RuntimeReceipt
}

// NewReceiptStore returns a ReceiptStore with the given ring buffer capacity.
func NewReceiptStore(cap int) *ReceiptStore {
	if cap <= 0 {
		cap = 100
	}
	return &ReceiptStore{
		entries: make([]runner.RuntimeReceipt, 0, cap),
		cap:     cap,
	}
}

// Push adds a receipt to the ring buffer and notifies subscribers.
// When capacity is reached the oldest entry is evicted.
func (s *ReceiptStore) Push(r runner.RuntimeReceipt) {
	s.mu.Lock()
	if len(s.entries) >= s.cap {
		// Evict oldest entry.
		copy(s.entries, s.entries[1:])
		s.entries = s.entries[:len(s.entries)-1]
	}
	s.entries = append(s.entries, r)
	// Snapshot subscribers under the write lock so we don't hold it while sending.
	subs := make([]chan runner.RuntimeReceipt, len(s.subs))
	copy(subs, s.subs)
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- r:
		default:
			// subscriber buffer full — drop (non-blocking).
		}
	}
}

// Last returns the last n receipts in insertion order (newest last).
// If n > len(entries) or n <= 0, all entries are returned.
func (s *ReceiptStore) Last(n int) []runner.RuntimeReceipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n <= 0 || n >= len(s.entries) {
		out := make([]runner.RuntimeReceipt, len(s.entries))
		copy(out, s.entries)
		return out
	}
	src := s.entries[len(s.entries)-n:]
	out := make([]runner.RuntimeReceipt, len(src))
	copy(out, src)
	return out
}

// subscribe returns a buffered channel that receives receipts on Push.
func (s *ReceiptStore) subscribe() chan runner.RuntimeReceipt {
	ch := make(chan runner.RuntimeReceipt, 8)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

// unsubscribe removes ch from the subscriber list and closes it.
func (s *ReceiptStore) unsubscribe(ch chan runner.RuntimeReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sub := range s.subs {
		if sub == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP handlers
// ──────────────────────────────────────────────────────────────────────────────

// receiptsHandler implements GET /v1/receipts — returns last N receipts.
// The optional ?limit=N query parameter caps the result set (default 20, max 100).
type receiptsHandler struct {
	store *ReceiptStore
}

// NewReceiptsHandler returns an http.Handler for GET /v1/receipts.
func NewReceiptsHandler(store *ReceiptStore) http.Handler {
	return &receiptsHandler{store: store}
}

func (h *receiptsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse optional ?limit=N (default 20, max 100).
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		if n > 100 {
			n = 100
		}
		limit = n
	}

	// receiptView is the projected shape for GET /v1/receipts.
	// Must match the SSE receiptPayload struct — no raw RuntimeReceipt serialization.
	type receiptView struct {
		Runtime         string `json:"runtime"`
		Provider        string `json:"provider"`
		Capability      string `json:"capability"`
		PolicyDecision  string `json:"policy_decision"`
		CredentialShape string `json:"credential_shape"`
		ExitCode        int    `json:"exit_code,omitempty"`
		TTL             int64  `json:"ttl,omitempty"` // nanoseconds
	}

	var raw []runner.RuntimeReceipt
	if h.store != nil {
		raw = h.store.Last(limit)
	}
	views := make([]receiptView, len(raw))
	for i, r := range raw {
		views[i] = receiptView{
			Runtime:         r.Runtime,
			Provider:        r.Provider,
			Capability:      r.Capability,
			PolicyDecision:  r.PolicyDecision,
			CredentialShape: r.CredentialShape,
			ExitCode:        r.ExitCode,
			TTL:             int64(r.TTL),
		}
	}
	writeJSON(w, map[string]interface{}{"receipts": views})
}

// receiptsStreamHandler implements GET /v1/receipts/stream — SSE endpoint.
type receiptsStreamHandler struct {
	store *ReceiptStore
}

// NewReceiptsStreamHandler returns an http.Handler for GET /v1/receipts/stream.
func NewReceiptsStreamHandler(store *ReceiptStore) http.Handler {
	return &receiptsStreamHandler{store: store}
}

func (h *receiptsStreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Subscribe before writing the initial heartbeat so that any Push that
	// races with the client reading the heartbeat is not lost. If the store is
	// nil we skip subscription and fall through to the heartbeat-only loop.
	var ch chan runner.RuntimeReceipt
	if h.store != nil {
		ch = h.store.subscribe()
		defer h.store.unsubscribe(ch)
	}

	// Initial heartbeat.
	fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
	flusher.Flush()

	// If no store, just block until client disconnects.
	if h.store == nil {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
				flusher.Flush()
			}
		}
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case receipt, ok := <-ch:
			if !ok {
				return
			}
			writeSSEReceiptEvent(w, receipt)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

// pushReceiptsHandler implements POST /v1/receipts — internal-only, CLI → keylatchd bridge.
//
// S-INV-12: the handler requires the X-Keylatch-IPC-Secret header to match the
// server's startup-time secret. This prevents foreign processes (different user
// or unprivileged attacker) from injecting fake receipts into the UI dashboard.
//
// The secret is a 32-byte random value generated at server startup. The CLI
// reads it from the same path-protected file the server writes it to, ensuring
// only same-UID processes with filesystem access can obtain it.
type pushReceiptsHandler struct {
	store     *ReceiptStore
	ipcSecret string // hex-encoded 32-byte secret; empty = accept all (test mode)
}

// NewPushReceiptsHandler returns an http.Handler for POST /v1/receipts.
// ipcSecret is the hex-encoded 32-byte startup secret. Pass "" to accept all
// (tests and environments where the IPC bridge is not used).
func NewPushReceiptsHandler(store *ReceiptStore) http.Handler {
	return &pushReceiptsHandler{store: store}
}

// NewPushReceiptsHandlerWithSecret returns an http.Handler for POST /v1/receipts
// that enforces the X-Keylatch-IPC-Secret header (S-INV-12).
func NewPushReceiptsHandlerWithSecret(store *ReceiptStore, ipcSecret string) http.Handler {
	return &pushReceiptsHandler{store: store, ipcSecret: ipcSecret}
}

func (h *pushReceiptsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// S-INV-12: reject requests from foreign processes.
	// When ipcSecret is set, require exact match on X-Keylatch-IPC-Secret.
	// The comparison is constant-time to prevent timing side-channels.
	if h.ipcSecret != "" {
		provided := r.Header.Get("X-Keylatch-IPC-Secret")
		// Constant-time comparison: always compare equal-length strings.
		// hmac.Equal handles the length-mismatch case safely.
		if !safeEqual(provided, h.ipcSecret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// S-RM-9: body size limit — receipts are small; 16 KiB is generous.
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var receipt runner.RuntimeReceipt
	if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if h.store != nil {
		h.store.Push(receipt)
	}
	w.WriteHeader(http.StatusNoContent)
}

// safeEqual performs a constant-time string comparison to prevent timing attacks.
func safeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// writeSSEReceiptEvent writes a single "receipt" SSE event.
func writeSSEReceiptEvent(w http.ResponseWriter, r runner.RuntimeReceipt) {
	type receiptPayload struct {
		Runtime         string `json:"runtime"`
		Provider        string `json:"provider"`
		Capability      string `json:"capability"`
		PolicyDecision  string `json:"policy_decision"`
		CredentialShape string `json:"credential_shape"`
		ExitCode        int    `json:"exit_code,omitempty"`
		TTL             int64  `json:"ttl,omitempty"` // nanoseconds
	}
	payload := receiptPayload{
		Runtime:         r.Runtime,
		Provider:        r.Provider,
		Capability:      r.Capability,
		PolicyDecision:  r.PolicyDecision,
		CredentialShape: r.CredentialShape,
		ExitCode:        r.ExitCode,
		TTL:             int64(r.TTL), // nanoseconds
	}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: {\"error\":\"marshal\"}\n\n")
		return
	}
	fmt.Fprintf(w, "event: receipt\ndata: %s\n\n", string(b))
}
