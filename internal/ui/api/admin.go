// Package api — admin route group for team governance UI.
//
// Security invariants:
//   - The caller's role comes only from server-side state for the request's
//     authenticated UI session (AdminHandler.SessionRole); no request header,
//     cookie value or token claim can name a role.
//   - All admin POST/PUT/DELETE require the UI's double-submit CSRF token.
//   - All output is value-free (member data HMACd).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/ui/csrf"
)

// adminEnabled reports whether the admin console ships in this build.
// Replaced in tests.
var adminEnabled = func() bool { return manifest.Current().Enabled("admin") }

// AdminHandler handles /admin/* routes for team governance.
// All routes enforce admin role and CSRF on mutations.
type AdminHandler struct {
	Team *team.Team
	// SessionRole returns the team role bound to the request's authenticated
	// UI session, looked up from server-side session state. It must not read
	// anything the client chooses beyond the session cookie it validates.
	// Nil, or ok=false, denies the request.
	SessionRole func(r *http.Request) (role team.Role, ok bool)
}

// ServeHTTP routes admin requests.
func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !adminEnabled() {
		writeAdminError(w, http.StatusNotFound, "admin console unavailable in this build")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/admin")

	if !h.requireAdmin(w, r) {
		return
	}

	if isMutation(r.Method) {
		if err := csrf.Validate(r); err != nil {
			writeAdminError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
	}

	switch {
	case path == "/team" || path == "/team/":
		h.teamHandler(w, r)
	case strings.HasPrefix(path, "/policy"):
		h.policyHandler(w, r)
	case strings.HasPrefix(path, "/audit"):
		h.auditHandler(w, r)
	case strings.HasPrefix(path, "/approvals"):
		h.approvalsHandler(w, r)
	case strings.HasPrefix(path, "/scim"):
		h.scimHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

// requireAdmin admits the request only when its authenticated session holds
// at least the admin role.
func (h *AdminHandler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if h.SessionRole == nil {
		writeAdminError(w, http.StatusForbidden, "missing authorization")
		return false
	}
	role, ok := h.SessionRole(r)
	if !ok {
		writeAdminError(w, http.StatusForbidden, "missing authorization")
		return false
	}
	if err := team.RequireRole(team.Member{Role: role}, team.RoleAdmin); err != nil {
		writeAdminError(w, http.StatusForbidden, "insufficient role")
		return false
	}
	return true
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// teamHandler handles /admin/team — member list, invite, remove, transfer.
func (h *AdminHandler) teamHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List members — value-free (emails HMACd).
		members := make([]map[string]interface{}, 0, len(h.Team.Members))
		for _, m := range h.Team.Members {
			members = append(members, map[string]interface{}{
				"id":        m.ID,
				"hmac":      m.HMAC, // HMACd
				"role":      string(m.Role),
				"status":    string(m.Status),
				"joined_at": m.JoinedAt.UTC().Format(time.RFC3339),
			})
		}
		writeJSON(w, map[string]interface{}{
			"team_id": h.Team.ID,
			"members": members,
			"count":   len(members),
		})

	case http.MethodPost:
		// Invite: create invite bundle.
		var body struct {
			EmailHMAC string `json:"email_hmac"`
			Role      string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		writeJSON(w, map[string]interface{}{
			"status":     "invited",
			"email_hmac": body.EmailHMAC,
			"role":       body.Role,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// policyHandler handles /admin/policy — install, status, diff, rollback.
func (h *AdminHandler) policyHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"status":     "active",
			"version":    1,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		})
	case http.MethodPost:
		writeJSON(w, map[string]interface{}{
			"status": "installed",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// auditHandler handles /admin/audit — export config, test.
func (h *AdminHandler) auditHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"export_configured": false,
		"adapters":          []string{},
	})
}

// approvalsHandler handles /admin/approvals — approval inbox and SSE stream.
func (h *AdminHandler) approvalsHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/approvals")

	// Route /admin/approvals/stream to the SSE handler.
	if path == "/stream" || path == "/stream/" {
		sseH := &AdminApprovalsSSEHandler{Team: h.Team}
		sseH.ServeHTTP(w, r)
		return
	}

	writeJSON(w, map[string]interface{}{
		"approvals": []interface{}{},
		"pending":   0,
	})
}

// scimHandler handles /admin/scim — SCIM proxy.
func (h *AdminHandler) scimHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"scim_enabled": false,
		"endpoint":     "127.0.0.1:8763",
	})
}

// writeAdminError writes a JSON error response.
func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
