package scim_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/scim"
)

func newTestTeam() *team.Team {
	return &team.Team{
		ID:      "team-test",
		Name:    "Test Team",
		Members: []team.Member{},
	}
}

func newTestServer() (*scim.Server, *team.Team) {
	t := newTestTeam()
	s := scim.NewServer(t, scim.ServerOpts{
		Addr:        "127.0.0.1:0",
		BearerToken: "test-token",
	})
	return s, t
}

func TestSCIM_RefusesNonLoopback(t *testing.T) {
	tt := newTestTeam()
	s := scim.NewServer(tt, scim.ServerOpts{
		Addr:        "0.0.0.0:8763",
		BearerToken: "token",
	})
	if err := s.Serve(t.Context()); err == nil {
		t.Error("expected error for non-loopback bind, got nil")
	}
}

func TestSCIM_UnauthenticatedRequest(t *testing.T) {
	s, _ := newTestServer()
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	// No Authorization header.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got %d, want 401", rec.Code)
	}
}

func TestSCIM_CreateUser(t *testing.T) {
	s, tt := newTestServer()
	handler := s.Handler()

	body := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "hmac-alice",
		"active":   true,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("create user: got %d, want 201, body: %s", rec.Code, rec.Body.String())
	}

	// Member should be added to team.
	if len(tt.Members) != 1 {
		t.Errorf("expected 1 member after create, got %d", len(tt.Members))
	}
}

func TestSCIM_DeleteUser(t *testing.T) {
	// N-6: RemoveMember writes to disk — use a temp dir.
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	s, tt := newTestServer()

	// Pre-populate a member.
	member := team.Member{
		ID:       "test-member-1",
		HMAC:     "hmac-bob",
		Role:     team.RoleDeveloper,
		JoinedAt: time.Now(),
		Status:   team.MemberActive,
	}
	tt.Members = append(tt.Members, member)

	// Write the initial team file so RemoveMember can persist.
	if err := team.Save(t.Context(), tt); err != nil {
		t.Fatalf("save team: %v", err)
	}

	handler := s.Handler()

	req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/test-member-1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("delete user: got %d, want 204, body: %s", rec.Code, rec.Body.String())
	}

	if tt.Members[0].Status != team.MemberRemoved {
		t.Errorf("member status after delete = %v, want removed", tt.Members[0].Status)
	}
}

func TestSCIM_ListUsers_ValueFree(t *testing.T) {
	s, tt := newTestServer()
	tt.Members = append(tt.Members, team.Member{
		ID:       "member-1",
		HMAC:     "hmac-of-alice-email",
		Role:     team.RoleDeveloper,
		JoinedAt: time.Now(),
		Status:   team.MemberActive,
	})

	handler := s.Handler()
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("list users: got %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	// The userName in the response should be the HMAC, not a raw email.
	// Raw emails contain "@" — verify none appear.
	if strings.Contains(body, "@example.com") {
		t.Error("list users response contains raw email — value-free invariant violated")
	}
}
