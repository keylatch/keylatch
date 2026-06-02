package api

import (
	"net/http"
	"strings"
)

// GatewayHandler handles POST /api/gateway/up|down, GET /api/gateway/status,
// POST /api/gateway/tokens (scope-gated).
//
// AllowTokenMinting must be true for POST /api/gateway/tokens to succeed.
// Set it to true only when the session scope is ScopeTokenMinting or higher.
type GatewayHandler struct {
	AllowTokenMinting bool
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/gateway")

	notImpl := func() {
		w.WriteHeader(http.StatusNotImplemented)
		writeJSON(w, map[string]string{
			"error":   "not_implemented",
			"message": "this feature is not yet available",
		})
	}

	switch {
	case path == "/up" && r.Method == http.MethodPost:
		notImpl()

	case path == "/down" && r.Method == http.MethodPost:
		notImpl()

	case path == "/status" && r.Method == http.MethodGet:
		notImpl()

	case path == "/tokens" && r.Method == http.MethodPost:
		// Scope-gated: only ScopeTokenMinting may mint tokens.
		if !h.AllowTokenMinting {
			http.Error(w, "forbidden: insufficient scope for token minting", http.StatusForbidden)
			return
		}
		notImpl()

	default:
		http.NotFound(w, r)
	}
}

// BrokerHandler handles POST /api/broker/dry-run (501 stub).
type BrokerHandler struct{}

func (h *BrokerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/broker/dry-run" && r.Method == http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"broker dry-run not yet available","code":"not_implemented"}`))
		return
	}
	http.NotFound(w, r)
}
