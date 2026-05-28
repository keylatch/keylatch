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

func newTestServer(t *testing.T, scope ui.UISessionScope) *ui.Server {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)

	srv, err := ui.New(ui.ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: k,
		Scope:      scope,
		Env:        func(string) string { return "" },
	})
	require.NoError(t, err)
	return srv
}

// TestCSP_AllRoutesHaveSecurityHeaders verifies that all served routes include
// the required security headers and that CSP does not permit unsafe-eval.
func TestCSP_AllRoutesHaveSecurityHeaders(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, ui.ScopeAdmin)

	// Bootstrap to get session cookie
	bootstrapURL := srv.BootstrapURL()
	path := bootstrapURL[len("http://127.0.0.1:0"):]
	bootstrapReq := httptest.NewRequest(http.MethodGet, path, nil)
	bootstrapRec := httptest.NewRecorder()
	srv.TestServeHTTP(bootstrapRec, bootstrapReq)
	require.Equal(t, http.StatusSeeOther, bootstrapRec.Code)
	sessionCookie := findCookieByName(bootstrapRec, "kl_session")
	require.NotNil(t, sessionCookie)

	routes := []string{"/", "/api/status"}
	for _, route := range routes {
		route := route
		t.Run(route, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, route, nil)
			if route != "/" {
				req.AddCookie(sessionCookie)
			}
			rec := httptest.NewRecorder()
			srv.TestServeHTTP(rec, req)

			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
				"route %s: Cache-Control must be no-store", route)
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"),
				"route %s: X-Frame-Options must be DENY", route)
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"),
				"route %s: X-Content-Type-Options must be nosniff", route)
			assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"),
				"route %s: Referrer-Policy must be no-referrer", route)

			csp := rec.Header().Get("Content-Security-Policy")
			assert.NotEmpty(t, csp, "route %s: CSP header must be present", route)
			assert.NotContains(t, csp, "unsafe-eval",
				"route %s: CSP must not allow unsafe-eval", route)
		})
	}
}

// TestCSP_NoCaching verifies that the API does not cache sensitive responses.
func TestCSP_NoCaching(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, ui.ScopeAdmin)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)

	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func findCookieByName(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
