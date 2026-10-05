package ui_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrapTokenNeverInURLAfterExchange verifies that the bootstrap
// token does not appear in any URL after the initial /__bootstrap?b=... exchange.
//
// the token appears ONLY in the initial URL. After the 303 redirect,
// it must never appear in the Location header, cookies, or response bodies.
func TestBootstrapTokenNeverInURLAfterExchange(t *testing.T) {
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

	bootstrapURL := srv.BootstrapURL()

	// Extract the token value from the bootstrap URL.
	var token string
	for _, param := range strings.Split(strings.SplitN(bootstrapURL, "?", 2)[1], "&") {
		if strings.HasPrefix(param, "b=") {
			token = strings.TrimPrefix(param, "b=")
		}
	}
	require.NotEmpty(t, token, "bootstrap token must be present in URL")

	// Perform the bootstrap exchange.
	path := bootstrapURL[len("http://127.0.0.1:0"):]
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	// the Location header must NOT contain the bootstrap token.
	location := rec.Header().Get("Location")
	assert.NotContains(t, location, token,
		"bootstrap token must not appear in redirect Location URL")

	// The cookie values must not contain the bootstrap token.
	for _, c := range rec.Result().Cookies() {
		assert.NotContains(t, c.Value, token,
			"cookie %s must not contain bootstrap token", c.Name)
	}

	// The response body must not contain the bootstrap token.
	assert.NotContains(t, rec.Body.String(), token,
		"response body must not contain bootstrap token after exchange")
}

// TestSecondBootstrapAttemptRejected verifies that replaying the
// bootstrap token returns 401, preventing token reuse.
func TestSecondBootstrapAttemptRejected(t *testing.T) {
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

	path := srv.BootstrapURL()[len("http://127.0.0.1:0"):]

	// First exchange: OK.
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	rec1 := httptest.NewRecorder()
	srv.TestServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusSeeOther, rec1.Code)

	// Second exchange: must be rejected.
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	rec2 := httptest.NewRecorder()
	srv.TestServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code,
		"replayed bootstrap token must be rejected")
}
