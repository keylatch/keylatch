package api

import (
	"net/http"
	"strings"
)

// ApprovalsHandler handles GET /api/approvals, GET /api/approvals/stream (SSE),
// and POST /api/approvals/{token}/approve|deny.
//
// The approval inbox is not implemented in M1 (F26): every reachable route
// returns an explicit unavailable response rather than a fake success or a
// list that can never contain a real pending request.
type ApprovalsHandler struct{}

func (h *ApprovalsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/approvals")

	switch path { //nolint:staticcheck // QF1002: default case has complex prefix matching incompatible with tagged switch
	case "", "/":
		if r.Method == http.MethodGet {
			h.unavailable(w)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case "/stream":
		if r.Method == http.MethodGet {
			h.unavailable(w)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		// POST /api/approvals/{token}/approve|deny
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		if len(parts) == 2 && r.Method == http.MethodPost && (parts[1] == "approve" || parts[1] == "deny") {
			h.unavailable(w)
		} else {
			http.NotFound(w, r)
		}
	}
}

// unavailable writes the honest M1 response: the approval inbox, its
// action endpoints, and its SSE stream are all unimplemented.
func (h *ApprovalsHandler) unavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	writeJSON(w, map[string]string{
		"error":   "not_implemented",
		"message": "the approval workflow is not available in M1",
	})
}
