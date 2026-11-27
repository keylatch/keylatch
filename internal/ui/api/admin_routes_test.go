package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/keylatch/keylatch/internal/ui/csrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxAdminRequest(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	}
	if method != http.MethodGet {
		withCSRF(req)
	}
	return req
}

func newAdminHandler(t *testing.T) *api.AdminHandler {
	t.Helper()
	api.EnableAdminConsole(t)
	return adminHandlerFor(team.RoleAdmin)
}

func TestAdminRoutes_ReadOnlyEndpoints(t *testing.T) {
	cases := []struct {
		path    string
		wantKey string
		wantVal interface{}
	}{
		{"/admin/audit", "export_configured", false},
		{"/admin/scim", "scim_enabled", false},
		{"/admin/approvals", "pending", float64(0)},
		{"/admin/policy", "status", "active"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodGet, tc.path, ""))
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var body map[string]interface{}
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
			assert.Equal(t, tc.wantVal, body[tc.wantKey])
		})
	}
}

func TestAdminRoutes_UnknownPathIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodGet, "/admin/nope", ""))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminRoutes_PolicyInstallWithCSRF(t *testing.T) {
	rec := httptest.NewRecorder()
	newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodPost, "/admin/policy", "{}"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"installed"`)
}

func TestAdminRoutes_MethodNotAllowed(t *testing.T) {
	for _, path := range []string{"/admin/policy", "/admin/team"} {
		rec := httptest.NewRecorder()
		newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodDelete, path, ""))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
	}
}

func TestAdminRoutes_TeamInvite(t *testing.T) {
	rec := httptest.NewRecorder()
	newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodPost, "/admin/team", `{"email_hmac":"h1","role":"developer"}`))
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, map[string]string{"status": "invited", "email_hmac": "h1", "role": "developer"}, body)
}

func TestAdminRoutes_TeamInviteInvalidBody(t *testing.T) {
	rec := httptest.NewRecorder()
	newAdminHandler(t).ServeHTTP(rec, mxAdminRequest(http.MethodPost, "/admin/team", "{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid request body")
}

func TestAdminRoutes_WrongCSRFTokenRejected(t *testing.T) {
	req := mxAdminRequest(http.MethodPost, "/admin/policy", "{}")
	req.Header.Set(csrf.HeaderName, "another-token")
	rec := httptest.NewRecorder()
	newAdminHandler(t).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid CSRF token")
}

func TestAdminRoutes_NoSessionRoleFailsClosed(t *testing.T) {
	api.EnableAdminConsole(t)
	cases := map[string]*api.AdminHandler{
		"no resolver":      {Team: newTestTeam()},
		"session not held": {Team: newTestTeam(), SessionRole: func(*http.Request) (team.Role, bool) { return team.RoleOwner, false }},
	}
	for name, h := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/team", nil))
		assert.Equal(t, http.StatusForbidden, rec.Code, name)
		assert.Contains(t, rec.Body.String(), "missing authorization", name)
	}
}

func TestAdminSSE_RejectsNonGetAndNonFlusher(t *testing.T) {
	h := &api.AdminApprovalsSSEHandler{Bus: &api.ApprovalBus{}}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/approvals/stream", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	w := &mxNoFlushWriter{header: http.Header{}}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/approvals/stream", nil))
	assert.Equal(t, http.StatusInternalServerError, w.code)
	assert.Contains(t, w.body.String(), "streaming not supported")
}

type mxNoFlushWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (m *mxNoFlushWriter) Header() http.Header         { return m.header }
func (m *mxNoFlushWriter) WriteHeader(code int)        { m.code = code }
func (m *mxNoFlushWriter) Write(b []byte) (int, error) { return m.body.Write(b) }
