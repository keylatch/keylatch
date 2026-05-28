package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBrowseRunner returns a mock runner that returns the given output and exit code.
func newBrowseRunner(out []byte, exitCode int) func(context.Context, string, []string) ([]byte, int, error) {
	return func(_ context.Context, _ string, _ []string) ([]byte, int, error) {
		return out, exitCode, nil
	}
}

// TestPMBrowseHandler_MethodNotAllowed verifies non-GET requests are rejected.
func TestPMBrowseHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := api.NewPMBrowseHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/pm-browse?pm=op", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestPMBrowseHandler_MissingPMParam returns 400 when pm param is absent.
func TestPMBrowseHandler_MissingPMParam(t *testing.T) {
	t.Parallel()
	h := api.NewPMBrowseHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestPMBrowseHandler_OP_Unauthenticated returns {authenticated:false, hint: "Run: op signin"}
// when the op CLI exits non-zero.
func TestPMBrowseHandler_OP_Unauthenticated(t *testing.T) {
	t.Parallel()

	runner := newBrowseRunner([]byte("error: not signed in"), 1)
	h := api.NewPMBrowseHandler(runner)

	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm=op", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, false, resp["authenticated"])
	assert.Equal(t, "Run: op signin", resp["hint"])
}

// TestPMBrowseHandler_OP_Authenticated returns {authenticated:true, items:[...]}
// when the op CLI exits 0 with valid JSON.
func TestPMBrowseHandler_OP_Authenticated(t *testing.T) {
	t.Parallel()

	itemsJSON := `[{"id":"abc123","title":"OpenRouter API Key"},{"id":"def456","title":"GitHub PAT"}]`
	runner := newBrowseRunner([]byte(itemsJSON), 0)
	h := api.NewPMBrowseHandler(runner)

	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm=op", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Authenticated bool `json:"authenticated"`
		Items         []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"items"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.True(t, resp.Authenticated)
	require.Len(t, resp.Items, 2)
	assert.Equal(t, "OpenRouter API Key", resp.Items[0].Title)
}

// TestPMBrowseHandler_AWSSM_Unauthenticated verifies hint for AWS.
func TestPMBrowseHandler_AWSSM_Unauthenticated(t *testing.T) {
	t.Parallel()

	runner := newBrowseRunner([]byte("error: no credentials"), 1)
	h := api.NewPMBrowseHandler(runner)

	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm=aws_sm", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, false, resp["authenticated"])
	assert.NotEmpty(t, resp["hint"])
}

// TestPMBrowseHandler_HashiVault_Unauthenticated verifies hint for vault.
func TestPMBrowseHandler_HashiVault_Unauthenticated(t *testing.T) {
	t.Parallel()

	runner := newBrowseRunner([]byte("error: permission denied"), 2)
	h := api.NewPMBrowseHandler(runner)

	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm=hashivault", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, false, resp["authenticated"])
}

// TestPMBrowseHandler_InvalidPM returns 400 for unknown pm value.
func TestPMBrowseHandler_InvalidPM(t *testing.T) {
	t.Parallel()

	h := api.NewPMBrowseHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm=doppler", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
