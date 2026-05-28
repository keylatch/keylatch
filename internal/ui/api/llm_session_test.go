package api_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLLMSession_WriteEndpointsReturn404 verifies that write endpoints return
// 404 when accessed via an LLM session (ScopeStatusOnly), not 403.
func TestLLMSession_WriteEndpointsReturn404(t *testing.T) {
	t.Parallel()

	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)

	srv, err := ui.New(ui.ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: k,
		Scope:      ui.ScopeStatusOnly,
		Env: func(key string) string {
			if key == "CLAUDE_CODE" {
				return "1"
			}
			return ""
		},
	})
	require.NoError(t, err)

	// Bootstrap to get session
	bootstrapPath := srv.BootstrapURL()[len("http://127.0.0.1:0"):]
	bootReq := httptest.NewRequest(http.MethodGet, bootstrapPath, nil)
	bootRec := httptest.NewRecorder()
	srv.TestServeHTTP(bootRec, bootReq)
	require.Equal(t, http.StatusSeeOther, bootRec.Code)

	sessionCookie := findCookieByName(bootRec, "kl_session")
	require.NotNil(t, sessionCookie)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/connections"},
		{http.MethodDelete, "/api/connections/test"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.AddCookie(sessionCookie)
			rec := httptest.NewRecorder()
			srv.TestServeHTTP(rec, req)
			assert.Equal(t, http.StatusNotFound, rec.Code,
				"LLM session: %s %s must return 404 not 403", tc.method, tc.path)
		})
	}
}

// TestLLMSession_CookieForgery_AuditLog verifies that a forged cookie
// returns 401 (the session validator catches forgery attempts).
func TestLLMSession_CookieForgery_401(t *testing.T) {
	t.Parallel()

	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)

	srv, err := ui.New(ui.ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: k,
		Scope:      ui.ScopeAdmin,
		Env:        func(string) string { return "" },
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "kl_session",
		Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
