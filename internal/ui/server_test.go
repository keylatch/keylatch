package ui_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signingKey32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func defaultOpts(t *testing.T) ui.ServerOptions {
	t.Helper()
	return ui.ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: signingKey32(t),
		Scope:      ui.ScopeAdmin,
		Env:        func(string) string { return "" },
	}
}

func TestNew_RequiresLoopbackBind(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.Bind = "0.0.0.0:7890"
	_, err := ui.New(opts)
	require.Error(t, err, "should reject external bind without flag")
}

func TestNew_AllowExternalBind_WithFlag(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.Bind = "0.0.0.0:0"
	opts.AllowExternalBind = true
	_, err := ui.New(opts)
	require.NoError(t, err)
}

func TestNew_ExternalBind_RejectedInLLMSession(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.Bind = "0.0.0.0:7890"
	opts.AllowExternalBind = true
	opts.Env = func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}
	_, err := ui.New(opts)
	require.Error(t, err, "must reject external bind in LLM session even with flag")
}

func TestNew_Require32ByteKey(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.SigningKey = make([]byte, 16)
	_, err := ui.New(opts)
	require.Error(t, err)
}

func TestServer_BootstrapHandler(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	url := srv.BootstrapURL()
	require.Contains(t, url, "/__bootstrap?b=")

	// Simulate a GET request to /__bootstrap
	req := httptest.NewRequest(http.MethodGet, url[len("http://127.0.0.1:0"):], nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code, "bootstrap should redirect with 303")
	// Token must not appear in redirect Location
	location := rec.Header().Get("Location")
	assert.NotContains(t, location, "b=", "token must not appear in redirect URL")
}

func TestServer_BootstrapConsumedOnce(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	url := srv.BootstrapURL()
	path := url[len("http://127.0.0.1:0"):]

	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusSeeOther, rec.Code)

	// Second attempt must fail
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	rec2 := httptest.NewRecorder()
	srv.TestServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
}

func TestServer_StatusEndpoint_RequiresSession(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, rec.Body.String(), "keylatch_daemon_uptime_seconds")
	assert.Contains(t, rec.Body.String(), "keylatch_gateway_requests_total")
}

func TestServer_StatusEndpoint_WithSession(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	// Bootstrap to get session cookie
	bootstrapURL := srv.BootstrapURL()
	path := bootstrapURL[len("http://127.0.0.1:0"):]
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	sessionCookie := findCookie(rec, "kl_session")
	require.NotNil(t, sessionCookie)

	// Now access /api/status with session cookie
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	srv.TestServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
}

func TestServer_LLMScope_WritesReturn404(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.Env = func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}
	opts.Scope = ui.ScopeStatusOnly
	srv, err := ui.New(opts)
	require.NoError(t, err)

	// Bootstrap
	bootstrapURL := srv.BootstrapURL()
	path := bootstrapURL[len("http://127.0.0.1:0"):]
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	sessionCookie := findCookie(rec, "kl_session")

	// POST /api/connections must return 404 (not 403) in LLM scope
	req2 := httptest.NewRequest(http.MethodPost, "/api/connections", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	srv.TestServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusNotFound, rec2.Code)
}

func TestServer_SecurityHeaders(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)

	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
}

func TestServer_GracefulShutdown(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx)
	}()

	// Give server a moment to start
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down gracefully")
	}
}

// findCookie finds a cookie by name in a recorded response.
func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
