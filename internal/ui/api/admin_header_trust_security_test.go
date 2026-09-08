//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package api

import (
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// KNOWN-FAILING (F38): AdminHandler authorizes solely from the
// caller-supplied X-Keylatch-Role header instead of a verified JWT/session,
// so any caller can self-assert an admin role.
func TestSecurityRegression_F38_AdminHeaderTrust(t *testing.T) {
	h := &AdminHandler{Team: &team.Team{}, JWTSigningKey: []byte("not-presented-to-client")}
	r := httptest.NewRequest("GET", "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", "admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("admin response without JWT using client supplied role header")
	}
}
