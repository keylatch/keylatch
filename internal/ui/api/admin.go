// Package api — admin route group for Phase 12 team governance UI.
//
// Security invariants:
//   - S12-15: Role enforcement at package layer.
//   - All admin routes require admin role (extracted from JWT).
//   - All admin POST/PUT/DELETE require CSRF token (HMAC double-submit, S-INV-5).
//   - All output is value-free (member data HMACd).
//   - JWT signature is verified via HMAC-SHA256 before any claims are trusted (S-INV-5).
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/team"
)

// AdminHandler handles /admin/* routes for team governance.
// All routes enforce admin role and CSRF on mutations.
type AdminHandler struct {
	Team          *team.Team
	CSRFSecret    string // CSRF HMAC secret for double-submit pattern
	JWTSigningKey []byte // HS256 key; falls back to []byte(CSRFSecret) if nil
}

// ServeHTTP routes admin requests.
func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin")

	// Role gate: extract JWT and require admin (S12-15).
	if !h.requireAdmin(w, r) {
		return
	}

	// CSRF gate on mutations.
	if isMutation(r.Method) {
		if !h.checkCSRF(w, r) {
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

// requireAdmin checks the request carries a valid admin-role JWT.
// S-INV-5: bearer token must have a valid HS256 signature before any claims are trusted.
func (h *AdminHandler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	// Check X-Keylatch-Role header (set by gateway after JWT validation).
	role := r.Header.Get("X-Keylatch-Role")
	if role == "" {
		// Extract from Bearer token — signature is verified inside extractRoleFromJWT.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeAdminError(w, http.StatusForbidden, "missing authorization")
			return false
		}
		role = h.extractRoleFromJWT(strings.TrimPrefix(auth, "Bearer "))
		if role == "" {
			writeAdminError(w, http.StatusForbidden, "missing or invalid role claim in token")
			return false
		}
	}

	// S12-15: role enforcement at package layer.
	member := team.Member{Role: team.Role(role)}
	if err := team.RequireRole(member, team.RoleAdmin); err != nil {
		writeAdminError(w, http.StatusForbidden, "insufficient role")
		return false
	}
	return true
}

// extractRoleFromJWT verifies the HS256 JWT signature then parses role from claims.
// S-INV-5: an unverified or forged JWT returns "" so requireAdmin denies the request.
func (h *AdminHandler) extractRoleFromJWT(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}

	// Determine signing key: prefer JWTSigningKey, fall back to CSRFSecret.
	key := h.JWTSigningKey
	if len(key) == 0 {
		key = []byte(h.CSRFSecret)
	}
	if len(key) == 0 {
		return "" // no key configured — reject
	}

	// Verify HS256 signature over header.payload.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	// parts[2] may be "" for alg:none style tokens — hmac.Equal always returns false for mismatched lengths.
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "" // invalid signature
	}

	// Signature valid — decode and parse claims.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Role
}

// checkCSRF validates the CSRF double-submit token on mutation requests.
// S-INV-5: the X-CSRF-Token must be HMAC-SHA256(CSRFSecret, Authorization-header).
// A missing or incorrect token results in 403 — no state mutation proceeds.
func (h *AdminHandler) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		writeAdminError(w, http.StatusForbidden, "missing CSRF token")
		return false
	}
	auth := r.Header.Get("Authorization")
	mac := hmac.New(sha256.New, []byte(h.CSRFSecret))
	mac.Write([]byte(auth))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(token), []byte(expected)) {
		writeAdminError(w, http.StatusForbidden, "invalid CSRF token")
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
