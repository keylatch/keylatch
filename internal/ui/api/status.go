package api

import (
	"net/http"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// StatusHandler handles GET /api/status.
type StatusHandler struct {
	Scope string
	Demo  bool
	Env   llmcontext.Lookup
}

func (h *StatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]interface{}{
		"ok":    true,
		"scope": h.Scope,
		"demo":  h.Demo,
	}
	if h.Demo {
		resp["demo_banner"] = "Demo mode — no real credentials are stored"
	}
	writeJSON(w, resp)
}

// AuditHandler handles GET /api/audit/summary.
type AuditHandler struct {
	Logger *audit.Logger
}

func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Stub: real implementation reads from audit log.
	writeJSON(w, map[string]interface{}{
		"totalEvents": 0,
		"lastEventAt": nil,
		"errorCount":  0,
		"deniedCount": 0,
	})
}

// AgentHandler handles GET /api/agent/snippet and POST /api/agent/setup.
type AgentHandler struct {
	Store connections.Store
	Env   llmcontext.Lookup
}

func (h *AgentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/agent/snippet":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.snippet(w, r)
	case "/api/agent/setup":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.setup(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *AgentHandler) snippet(w http.ResponseWriter, _ *http.Request) {
	// Value-free: snippet shows usage, not credentials.
	writeJSON(w, map[string]interface{}{
		"language":       "bash",
		"snippet":        "# Run: keylatch gateway up\nexport KEYLATCH_GATEWAY_URL=http://127.0.0.1:7878",
		"noSecretsBadge": true,
	})
}

func (h *AgentHandler) setup(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":    "configured",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
