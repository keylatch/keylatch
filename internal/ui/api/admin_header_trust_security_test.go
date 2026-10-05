package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// A client-supplied role header or bearer token must never grant admin: the
// role comes only from the authenticated session.
func TestAdminRoleHeaderIgnored(t *testing.T) {
	EnableAdminConsole(t)

	type headerSet map[string][]string
	forged := []headerSet{
		{"X-Keylatch-Role": {"admin"}},
		{"X-Keylatch-Role": {"owner"}},
		{"x-keylatch-role": {"ADMIN"}},
		{"X-KEYLATCH-ROLE": {"Owner"}},
		{"X-Keylatch-Role": {"developer", "admin"}},
		{"X-Keylatch-Role": {"admin", "owner"}},
		{"X-Keylatch-Role": {"admin"}, "Authorization": {"Bearer e30.eyJyb2xlIjoiYWRtaW4ifQ."}},
	}
	sessions := map[string]func(*http.Request) (team.Role, bool){
		"no session":        nil,
		"rejected session":  func(*http.Request) (team.Role, bool) { return "", false },
		"developer session": func(*http.Request) (team.Role, bool) { return team.RoleDeveloper, true },
		"viewer session":    func(*http.Request) (team.Role, bool) { return team.RoleViewer, true },
	}
	for name, sessionRole := range sessions {
		for _, hs := range forged {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				r := httptest.NewRequest(method, "/admin/team", nil)
				for k, vs := range hs {
					for _, v := range vs {
						r.Header.Add(k, v)
					}
				}
				w := httptest.NewRecorder()
				(&AdminHandler{Team: &team.Team{}, SessionRole: sessionRole}).ServeHTTP(w, r)
				if w.Code != http.StatusForbidden {
					t.Errorf("%s, %s with %v: got %d, want 403", name, method, hs, w.Code)
				}
			}
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", "viewer")
	w := httptest.NewRecorder()
	admin := func(*http.Request) (team.Role, bool) { return team.RoleAdmin, true }
	(&AdminHandler{Team: &team.Team{}, SessionRole: admin}).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin session with a lower header role: got %d, want 200", w.Code)
	}
}
