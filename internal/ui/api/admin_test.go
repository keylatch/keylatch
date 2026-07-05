package api_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/approval"
	"github.com/keylatch/keylatch/internal/ui/api"
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

const testCSRFSecret = "test-secret"

// newAdminHandler returns an AdminHandler wired to the test team.
func newAdminHandler() *api.AdminHandler {
	return &api.AdminHandler{
		Team:       newTestTeam(),
		CSRFSecret: testCSRFSecret,
		// JWTSigningKey falls back to []byte(CSRFSecret) when nil.
	}
}

// csrfTokenFor computes the correct HMAC-SHA256 CSRF token for the given Authorization header value.
func csrfTokenFor(auth string) string {
	mac := hmac.New(sha256.New, []byte(testCSRFSecret))
	mac.Write([]byte(auth))
	return hex.EncodeToString(mac.Sum(nil))
}

// --- Role gate ---

func TestAdminHandler_NonAdmin_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleDeveloper))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for developer role, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected error field in JSON response")
	}
}

func TestAdminHandler_Viewer_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleViewer))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for viewer role, got %d", w.Code)
	}
}

func TestAdminHandler_NoAuth_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	// No X-Keylatch-Role, no Authorization header.
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 with no auth, got %d", w.Code)
	}
}

func TestAdminHandler_AdminRole_Passes(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin role, got %d", w.Code)
	}
}

func TestAdminHandler_OwnerRole_Passes(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleOwner))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for owner role, got %d", w.Code)
	}
}

// mintRoleJWT mints a properly HS256-signed JWT with the given role claim.
// Signs with testCSRFSecret (which is the fallback JWTSigningKey when JWTSigningKey is nil).
// admin.go now verifies the signature — unsigned tokens must be rejected.
func mintRoleJWT(role string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]string{"role": role})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, []byte(testCSRFSecret))
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig
}

// TestAdminJWT_AlgNone_Returns403 verifies that an alg:none style JWT (empty signature)
// is rejected with 403. The forged-signature sub-case is already covered by
// TestAdminHandler_UnsignedJWT_Returns403 and is not duplicated here.
func TestAdminJWT_AlgNone_Returns403(t *testing.T) {
	h := newAdminHandler()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]string{"role": string(team.RoleAdmin)})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	// alg:none style — empty signature.
	noneJWT := header + "." + payload + "."
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+noneJWT)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("alg:none JWT must return 403, got %d", w.Code)
	}
}

// TestAdminHandler_UnsignedJWT_Returns403 is the gate:
// a JWT with a forged/unsigned signature must be rejected with 403.
func TestAdminHandler_UnsignedJWT_Returns403(t *testing.T) {
	h := newAdminHandler()
	// Build a JWT manually with a fake signature (not HMAC'd with test-secret).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]string{"role": string(team.RoleAdmin)})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	fakeSig := base64.RawURLEncoding.EncodeToString([]byte("forged-signature"))
	forgedJWT := header + "." + payload + "." + fakeSig

	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+forgedJWT)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unsigned JWT, got %d", w.Code)
	}
}

// --- Bearer token role extraction (M-5) ---

func TestAdminHandler_BearerToken_DeveloperRole_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+mintRoleJWT(string(team.RoleDeveloper)))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("developer bearer token: expected 403, got %d", w.Code)
	}
}

func TestAdminHandler_BearerToken_ViewerRole_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+mintRoleJWT(string(team.RoleViewer)))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("viewer bearer token: expected 403, got %d", w.Code)
	}
}

func TestAdminHandler_BearerToken_AdminRole_Passes(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+mintRoleJWT(string(team.RoleAdmin)))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("admin bearer token: expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_BearerToken_OwnerRole_Passes(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("Authorization", "Bearer "+mintRoleJWT(string(team.RoleOwner)))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("owner bearer token: expected 200, got %d", w.Code)
	}
}

func TestAdminHandler_BearerToken_NoAuth_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	// No auth header at all.
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("no auth: expected 403, got %d", w.Code)
	}
}

// --- CSRF gate ---

func TestAdminHandler_MutationWithoutCSRF_Returns403(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodPost, "/admin/team", strings.NewReader(`{"email_hmac":"hmac-x","role":"developer"}`))
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	r.Header.Set("Content-Type", "application/json")
	// No X-CSRF-Token header.
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing CSRF token, got %d", w.Code)
	}
}

func TestAdminHandler_MutationWithCSRF_Passes(t *testing.T) {
	h := newAdminHandler()
	body := `{"email_hmac":"hmac-x","role":"developer"}`
	// Use X-Keylatch-Role (not Bearer) so the CSRF HMAC is computed over the Authorization header.
	// When using X-Keylatch-Role, Authorization is empty; HMAC("", secret) is used for CSRF.
	authHeader := "" // no Bearer token when using X-Keylatch-Role
	r := httptest.NewRequest(http.MethodPost, "/admin/team", strings.NewReader(body))
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfTokenFor(authHeader))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid CSRF token, got %d", w.Code)
	}
}

// --- Team list value-free ---

func TestAdminHandler_TeamList_ValueFree(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/team", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	// Value-free: no raw emails in response.
	if strings.Contains(body, "@example.com") || strings.Contains(body, "@") {
		t.Error("team list response contains raw email — value-free invariant violated")
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if resp["team_id"] != "team-test" {
		t.Errorf("team_id = %v, want team-test", resp["team_id"])
	}
	members, ok := resp["members"].([]interface{})
	if !ok {
		t.Fatal("members field missing or wrong type")
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

// --- Policy handler ---

func TestAdminHandler_PolicyGet(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/policy", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if resp["status"] != "active" {
		t.Errorf("policy status = %v, want active", resp["status"])
	}
}

// --- Approvals handler ---

func TestAdminHandler_ApprovalsGet(t *testing.T) {
	h := newAdminHandler()
	r := httptest.NewRequest(http.MethodGet, "/admin/approvals", nil)
	r.Header.Set("X-Keylatch-Role", string(team.RoleAdmin))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
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
