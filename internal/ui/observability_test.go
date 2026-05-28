package ui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealthEndpoint_NoAuthRequired asserts that GET /health succeeds
// without any session cookie. External liveness probes (kubelet, docker
// healthcheck, load-balancer health checks) cannot authenticate, so the
// endpoint must be reachable without credentials.
func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "GET /health must return 200")
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
	assert.NotEmpty(t, body["version"], "version must be set")
	assert.Contains(t, body["version"], "keylatch", "version string should reference keylatch")

	// Value-free contract: only "status" and "version" keys. No host,
	// no scope, no audit counters, no env hints.
	for k := range body {
		if k != "status" && k != "version" {
			t.Errorf("/health response must not include key %q", k)
		}
	}
}

// TestHealthEndpoint_RejectsNonGET asserts that non-GET methods return
// 405. This is consistent with the gateway /health endpoint's contract.
func TestHealthEndpoint_RejectsNonGET(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/health", nil)
		rec := httptest.NewRecorder()
		srv.TestServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code,
			"/health must reject %s", method)
	}
}

// TestExperimentalEndpoint_NoAuthRequired asserts that GET /v1/config/experimental
// succeeds without authentication and returns a JSON boolean flag.
func TestExperimentalEndpoint_NoAuthRequired(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/config/experimental", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "GET /v1/config/experimental must return 200")
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]bool
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	_, ok := body["experimental"]
	assert.True(t, ok, "response must contain 'experimental' field")
}

// TestExperimentalEndpoint_RejectsNonGET asserts that non-GET methods return 405.
func TestExperimentalEndpoint_RejectsNonGET(t *testing.T) {
	t.Parallel()
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/config/experimental", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestHealthEndpoint_InLLMScope asserts that /health is available even
// when the server is in ScopeStatusOnly (LLM session ceiling). The
// existing rule that "/api/* returns 404 in LLM scope" must not extend
// to /health — liveness probes are not credential-bearing.
func TestHealthEndpoint_InLLMScope(t *testing.T) {
	t.Parallel()
	opts := defaultOpts(t)
	opts.Scope = ui.ScopeStatusOnly
	srv, err := ui.New(opts)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "/health must be available in LLM scope")
}
