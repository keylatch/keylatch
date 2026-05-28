package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectionsHandler_POST_WithFields_Direct creates a connection with a direct-mode field.
func TestConnectionsHandler_POST_WithFields_Direct(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()
	h := &api.ConnectionsHandler{Store: store}

	body := `{
		"provider": "openrouter",
		"fields": [
			{"name": "api_key", "mode": "direct", "value": "sk-test-direct"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"provider":"openrouter"`)
}

// TestConnectionsHandler_POST_WithFields_Reference validates and stores a reference URI.
func TestConnectionsHandler_POST_WithFields_Reference(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()
	h := &api.ConnectionsHandler{Store: store}

	body := `{
		"provider": "openrouter",
		"fields": [
			{"name": "api_key", "mode": "reference", "uri": "op://Personal/OpenRouter/api_key"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestConnectionsHandler_POST_InvalidReferenceURI returns 422 on malformed URI.
func TestConnectionsHandler_POST_InvalidReferenceURI(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()
	h := &api.ConnectionsHandler{Store: store}

	body := `{
		"provider": "openrouter",
		"fields": [
			{"name": "api_key", "mode": "reference", "uri": "aws-sm://"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	var errResp struct {
		Errors []map[string]string `json:"errors"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.Len(t, errResp.Errors, 1)
	assert.Equal(t, "api_key", errResp.Errors[0]["field"])
}

// TestConnectionDetailHandler_PUT_UpdateFieldModes updates field modes for an existing connection.
func TestConnectionDetailHandler_PUT_UpdateFieldModes(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()

	// Create connection first.
	create := &api.ConnectionsHandler{Store: store}
	createBody := `{"provider":"openrouter","fields":[{"name":"api_key","mode":"direct","value":"sk-test"}]}`
	create.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(createBody)))

	// Update to reference mode.
	detail := &api.ConnectionDetailHandler{Store: store}
	updateBody := `{"fields":[{"name":"api_key","mode":"reference","uri":"op://Personal/OpenRouter/credential"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/connections/openrouter", bytes.NewBufferString(updateBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	detail.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "updated", resp["status"])
}

// TestConnectionDetailHandler_PUT_InvalidURI returns 422 when the URI is malformed.
func TestConnectionDetailHandler_PUT_InvalidURI(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()

	// Create connection.
	create := &api.ConnectionsHandler{Store: store}
	createBody := `{"provider":"openrouter","fields":[{"name":"api_key","mode":"direct","value":"sk-test"}]}`
	create.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(createBody)))

	// Attempt update with bad URI.
	detail := &api.ConnectionDetailHandler{Store: store}
	badBody := `{"fields":[{"name":"api_key","mode":"reference","uri":"hashivault://"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/connections/openrouter", bytes.NewBufferString(badBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	detail.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// TestConnectionDetailHandler_DELETE removes a connection.
func TestConnectionDetailHandler_DELETE(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()

	// Create connection.
	create := &api.ConnectionsHandler{Store: store}
	createBody := `{"provider":"openrouter","fields":[{"name":"api_key","mode":"direct","value":"sk-test"}]}`
	create.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(createBody)))

	// Delete it.
	detail := &api.ConnectionDetailHandler{Store: store}
	req := httptest.NewRequest(http.MethodDelete, "/api/connections/openrouter", nil)
	rec := httptest.NewRecorder()
	detail.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
}

// TestConnectionsHandler_GET_ReturnsFieldsArray verifies the enriched response shape.
func TestConnectionsHandler_GET_ReturnsFieldsArray(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	store := newAPIMemoryStore()

	// Create a connection.
	create := &api.ConnectionsHandler{Store: store}
	createBody := `{"provider":"openrouter","fields":[{"name":"api_key","mode":"direct","value":"sk-test"}]}`
	create.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(createBody)))

	// List connections and verify shape.
	list := &api.ConnectionsHandler{Store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rec := httptest.NewRecorder()
	list.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Connections []struct {
			ID       string `json:"id"`
			Provider string `json:"provider"`
			Fields   []struct {
				Name string `json:"name"`
				Mode string `json:"mode"`
			} `json:"fields"`
		} `json:"connections"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Connections, 1)
	assert.Equal(t, "openrouter", resp.Connections[0].Provider)
	assert.NotEmpty(t, resp.Connections[0].ID)
	require.Len(t, resp.Connections[0].Fields, 1)
	assert.Equal(t, "api_key", resp.Connections[0].Fields[0].Name)
	assert.Equal(t, "direct", resp.Connections[0].Fields[0].Mode)
}
