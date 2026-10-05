package api_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/approval"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/keylatch/keylatch/internal/ui/csrf"
)

// newTestTeam returns a minimal team for admin handler tests.
func newTestTeam() *team.Team {
	return &team.Team{
		ID:   "team-test",
		Name: "Test Team",
		Members: []team.Member{
			{
				ID:       "member-admin",
				HMAC:     "hmac-admin",
				Role:     team.RoleAdmin,
				Status:   team.MemberActive,
				JoinedAt: time.Now().UTC(),
			},
			{
				ID:       "member-dev",
				HMAC:     "hmac-dev",
				Role:     team.RoleDeveloper,
				Status:   team.MemberActive,
				JoinedAt: time.Now().UTC(),
			},
		},
	}
}

// adminHandlerFor returns a handler whose authenticated session carries role.
func adminHandlerFor(role team.Role) *api.AdminHandler {
	return &api.AdminHandler{
		Team:        newTestTeam(),
		SessionRole: func(*http.Request) (team.Role, bool) { return role, true },
	}
}

func serveAdmin(h *api.AdminHandler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func withCSRF(r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: "csrf-token"})
	r.Header.Set(csrf.HeaderName, "csrf-token")
	return r
}

func TestAdminHandler_UnavailableBuildDeniesAdminSession(t *testing.T) {
	w := serveAdmin(adminHandlerFor(team.RoleAdmin), httptest.NewRequest(http.MethodGet, "/admin/team", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin console in an unavailable build: got %d, want 404", w.Code)
	}
}

func TestAdminHandler_SessionRoleGate(t *testing.T) {
	api.EnableAdminConsole(t)
	cases := []struct {
		role team.Role
		want int
	}{
		{team.RoleViewer, http.StatusForbidden},
		{team.RoleDeveloper, http.StatusForbidden},
		{team.Role("ADMIN"), http.StatusForbidden},
		{team.Role(""), http.StatusForbidden},
		{team.RoleAdmin, http.StatusOK},
		{team.RoleOwner, http.StatusOK},
	}
	for _, tc := range cases {
		w := serveAdmin(adminHandlerFor(tc.role), httptest.NewRequest(http.MethodGet, "/admin/policy", nil))
		if w.Code != tc.want {
			t.Errorf("session role %q: got %d, want %d", tc.role, w.Code, tc.want)
		}
	}
}

func TestAdminHandler_NoSessionDenied(t *testing.T) {
	api.EnableAdminConsole(t)
	unauthenticated := &api.AdminHandler{
		Team:        newTestTeam(),
		SessionRole: func(*http.Request) (team.Role, bool) { return "", false },
	}
	for _, h := range []*api.AdminHandler{{Team: newTestTeam()}, unauthenticated} {
		if w := serveAdmin(h, httptest.NewRequest(http.MethodGet, "/admin/team", nil)); w.Code != http.StatusForbidden {
			t.Errorf("no authenticated session: got %d, want 403", w.Code)
		}
	}
}

// --- CSRF gate ---

func TestAdminHandler_MutationWithoutCSRF_Returns403(t *testing.T) {
	api.EnableAdminConsole(t)
	w := serveAdmin(adminHandlerFor(team.RoleAdmin), httptest.NewRequest(http.MethodPost, "/admin/policy", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF token: got %d, want 403", w.Code)
	}
}

func TestAdminHandler_MutationWithMismatchedCSRF_Returns403(t *testing.T) {
	api.EnableAdminConsole(t)
	r := httptest.NewRequest(http.MethodPost, "/admin/policy", nil)
	r.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: "csrf-token"})
	r.Header.Set(csrf.HeaderName, "other-token")
	if w := serveAdmin(adminHandlerFor(team.RoleAdmin), r); w.Code != http.StatusForbidden {
		t.Fatalf("mismatched CSRF token: got %d, want 403", w.Code)
	}
}

func TestAdminHandler_MutationWithCSRF_Passes(t *testing.T) {
	api.EnableAdminConsole(t)
	r := withCSRF(httptest.NewRequest(http.MethodPost, "/admin/policy", nil))
	if w := serveAdmin(adminHandlerFor(team.RoleAdmin), r); w.Code != http.StatusOK {
		t.Fatalf("valid CSRF token: got %d, want 200", w.Code)
	}
}

// --- Team list value-free ---

func TestAdminHandler_TeamList_ValueFree(t *testing.T) {
	api.EnableAdminConsole(t)
	w := serveAdmin(adminHandlerFor(team.RoleAdmin), httptest.NewRequest(http.MethodGet, "/admin/team", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("team list: got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "@") {
		t.Error("team list contains a raw email")
	}
	if !strings.Contains(body, "hmac-admin") {
		t.Errorf("team list missing member HMAC: %s", body)
	}
}

func TestAdminHandler_ApprovalsGet(t *testing.T) {
	api.EnableAdminConsole(t)
	w := serveAdmin(adminHandlerFor(team.RoleAdmin), httptest.NewRequest(http.MethodGet, "/admin/approvals", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("approvals: got %d", w.Code)
	}
}

// --- SSE approval inbox ---

// TestAdminApprovalsSSE_HeartbeatOnConnect verifies that the SSE endpoint
// emits a heartbeat immediately upon connection.
func TestAdminApprovalsSSE_HeartbeatOnConnect(t *testing.T) {
	bus := &api.ApprovalBus{}
	h := &api.AdminApprovalsSSEHandler{
		Team: newTestTeam(),
		Bus:  bus,
	}

	// Cancel context after a short delay to terminate the SSE stream.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/admin/approvals/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "event: heartbeat") {
		t.Errorf("SSE stream did not contain heartbeat event; body: %q", body)
	}
	if !strings.Contains(body, "data:") {
		t.Errorf("SSE stream missing data line; body: %q", body)
	}
}

// TestAdminApprovalsSSE_EmitsApprovalEvent verifies that a published approval
// event appears in the SSE stream within 1s (emit-within-1s guarantee).
func TestAdminApprovalsSSE_EmitsApprovalEvent(t *testing.T) {
	bus := &api.ApprovalBus{}
	h := &api.AdminApprovalsSSEHandler{
		Team: newTestTeam(),
		Bus:  bus,
	}

	// We use a pipe to read SSE lines as they arrive.
	pr, pw := io.Pipe()

	w := &pipeResponseWriter{pw: pw, header: make(http.Header), code: http.StatusOK}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/admin/approvals/stream", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, r)
		pw.Close()
	}()

	// Publish an approval event after a short delay (to ensure handler is listening).
	go func() {
		time.Sleep(50 * time.Millisecond)
		req, _ := approval.Create(context.Background(), "write", "prod:db", team.Member{
			ID:   "requester",
			HMAC: "hmac-requester",
			Role: team.RoleDeveloper,
		}, approval.ModeTwoPerson, 2, 2)
		api.PublishApprovalOnBus(bus, req)
	}()

	// Read SSE lines until we see an approval event or timeout.
	scanner := bufio.NewScanner(pr)
	found := false
	deadline := time.Now().Add(1 * time.Second)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "event: approval") {
			found = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}
	cancel() // disconnect

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("handler did not terminate after context cancel")
	}

	if !found {
		t.Error("SSE stream did not emit approval event within 1s")
	}
}

// TestAdminApprovalsSSE_Disconnect verifies the handler exits cleanly
// when the client disconnects (context cancel).
func TestAdminApprovalsSSE_Disconnect(t *testing.T) {
	bus := &api.ApprovalBus{}
	h := &api.AdminApprovalsSSEHandler{
		Team: newTestTeam(),
		Bus:  bus,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/admin/approvals/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(w, r)
	elapsed := time.Since(start)

	// Handler should terminate promptly after context cancel (within 500ms).
	if elapsed > 500*time.Millisecond {
		t.Errorf("handler took %v to terminate after disconnect, want < 500ms", elapsed)
	}
}

// TestAdminApprovalsSSE_SSEPayload_ValueFree verifies that SSE approval
// events never contain raw member emails or IDs.
func TestAdminApprovalsSSE_SSEPayload_ValueFree(t *testing.T) {
	bus := &api.ApprovalBus{}
	h := &api.AdminApprovalsSSEHandler{
		Team: newTestTeam(),
		Bus:  bus,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Publish before stream starts — event will sit in buffer.
	go func() {
		time.Sleep(10 * time.Millisecond)
		req, _ := approval.Create(context.Background(), "inject", "openrouter:dev", team.Member{
			ID:   "requester",
			HMAC: "hmac-requester-noemail",
			Role: team.RoleDeveloper,
		}, approval.ModeTwoPerson, 2, 2)
		api.PublishApprovalOnBus(bus, req)
	}()

	r := httptest.NewRequest(http.MethodGet, "/admin/approvals/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, "@") || strings.Contains(body, "example.com") {
		t.Errorf("SSE payload contains raw email — value-free invariant violated: %q", body)
	}
}

// pipeResponseWriter implements http.ResponseWriter + http.Flusher using an io.PipeWriter.
type pipeResponseWriter struct {
	pw     *io.PipeWriter
	header http.Header
	code   int
}

func (p *pipeResponseWriter) Header() http.Header         { return p.header }
func (p *pipeResponseWriter) WriteHeader(code int)        { p.code = code }
func (p *pipeResponseWriter) Write(b []byte) (int, error) { return p.pw.Write(b) }
func (p *pipeResponseWriter) Flush()                      {}
