package api

import (
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// AdminHandler is gated unavailable — every request is denied
// before the role/CSRF checks run, so the caller-supplied X-Keylatch-Role
// header can no longer authorize anything, with or without a JWT. Real
// server-authenticated role/full-claims/active-membership verification is
// expansion work for when the admin surface re-enters scope.
func TestSecurityRegression_AdminHeaderTrust(t *testing.T) {
	h := &AdminHandler{Team: &team.Team{}, JWTSigningKey: []byte("not-presented-to-client")}
	r := httptest.NewRequest("GET", "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", "admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("admin response without JWT using client supplied role header")
	}
}
