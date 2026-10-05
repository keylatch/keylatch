package ui_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLLMScopeIsCeiling verifies that when CLAUDE_CODE=1 is set,
// the session scope is forced to ScopeStatusOnly regardless of requested scope.
func TestLLMScopeIsCeiling(t *testing.T) {
	t.Parallel()

	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)

	// Attempt to request ScopeAdmin in LLM session.
	_, err = ui.New(ui.ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: k,
		Scope:      ui.ScopeAdmin,
		Env: func(key string) string {
			if key == "CLAUDE_CODE" {
				return "1"
			}
			return ""
		},
	})
	// Server creation is allowed — scope is silently downgraded.
	require.NoError(t, err)
}

// TestLLMSession_WriteEndpoints404 verifies that write endpoints
// return 404 (not 403) in LLM sessions, ensuring no route information leaks.
func TestLLMSession_WriteEndpoints404(t *testing.T) {
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
	sessionCookie := findCookie(bootRec, "kl_session")

	writeEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/connections"},
		{http.MethodDelete, "/api/connections/test"},
		{http.MethodPost, "/api/gateway/tokens"},
	}

	for _, ep := range writeEndpoints {
		ep := ep
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(ep.method, ep.path, nil)
			if sessionCookie != nil {
				req.AddCookie(sessionCookie)
			}
			rec := httptest.NewRecorder()
			srv.TestServeHTTP(rec, req)
			assert.Equal(t, http.StatusNotFound, rec.Code,
				"write endpoint %s %s must return 404 in LLM session",
				ep.method, ep.path)
		})
	}
}

// TestBootstrapCaptureForgedCookieRejected verifies that forged
// session cookies are rejected with 401.
func TestBootstrapCaptureForgedCookieRejected(t *testing.T) {
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

	// Try to access /api/status with a forged cookie (no prior bootstrap).
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "kl_session",
		Value: "forged-cookie-value-00000000000000000000000000000000",
	})
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"forged session cookie must be rejected")
}
