package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ApprovalsHandler handles GET /api/approvals, GET /api/approvals/stream (SSE),
// and POST /api/approvals/{token}/approve|deny.
type ApprovalsHandler struct{}

func (h *ApprovalsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/approvals")

	switch path { //nolint:staticcheck // QF1002: default case has complex prefix matching incompatible with tagged switch
	case "", "/":
		if r.Method == http.MethodGet {
			h.list(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case "/stream":
		if r.Method == http.MethodGet {
			h.stream(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		// POST /api/approvals/{token}/approve|deny
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		if len(parts) == 2 && r.Method == http.MethodPost {
			token := parts[0]
			action := parts[1]
			h.action(w, r, token, action)
		} else {
			http.NotFound(w, r)
		}
	}
}

func (h *ApprovalsHandler) list(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{"approvals": []interface{}{}})
}

// stream implements Server-Sent Events (SSE) for FIND-020.
func (h *ApprovalsHandler) stream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial heartbeat.
	fmt.Fprintf(w, "event: heartbeat\ndata: {\"time\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
	flusher.Flush()

	// Block until client disconnects.
	<-r.Context().Done()
}

func (h *ApprovalsHandler) action(w http.ResponseWriter, r *http.Request, token, action string) {
	if action != "approve" && action != "deny" {
		http.NotFound(w, r)
		return
	}
	resp := map[string]string{
		"token":  token,
		"action": action,
		"status": "accepted",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
