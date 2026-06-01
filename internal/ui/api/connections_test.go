package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var apiRegistryOnce sync.Once

func initAPIRegistry(t *testing.T) {
	t.Helper()
	apiRegistryOnce.Do(func() {
		require.NoError(t, registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup))
	})
}

type apiMemoryStore struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newAPIMemoryStore() *apiMemoryStore {
	return &apiMemoryStore{entries: make(map[string][]byte)}
}

func (s *apiMemoryStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.entries[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := append([]byte(nil), v...)
	return cp, backend.Meta{Path: path, Backend: "memory", Version: 1}, nil
}

func (s *apiMemoryStore) Set(_ context.Context, path string, value []byte, meta backend.Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	s.entries[path] = append([]byte(nil), value...)
	return nil
}

func (s *apiMemoryStore) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]backend.Entry, 0)
	for path := range s.entries {
		if strings.HasPrefix(path, prefix) {
			out = append(out, backend.Entry{Meta: backend.Meta{Path: path, Backend: "memory", Version: 1}, Exists: true})
		}
	}
	return out, nil
}

func (s *apiMemoryStore) Delete(_ context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[path]; !ok {
		return backend.ErrNotFound
	}
	delete(s.entries, path)
	return nil
}

func TestConnectionsHandler_GET_ValueFree(t *testing.T) {
	t.Parallel()
	h := &api.ConnectionsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Canary: response must not contain Phase10 sentinel.
	canary.AssertNoLeak(t,
		[]string{canary.Phase10Sentinel},
		canary.JSONResponse(rec.Body.String()),
	)
}

func TestConnectionsHandler_GET_ReturnsConnections(t *testing.T) {
	t.Parallel()
	h := &api.ConnectionsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body struct {
		Connections []interface{} `json:"connections"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.NotNil(t, body.Connections)
}

func TestConnectionsHandler_POST_ValidRequest(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	h := &api.ConnectionsHandler{Store: newAPIMemoryStore()}
	body := `{"provider":"openrouter","fields":{"api_key":"test-key"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"provider":"openrouter"`)
}

func TestConnectionsHandler_POST_MissingProvider(t *testing.T) {
	t.Parallel()
	h := &api.ConnectionsHandler{Store: newAPIMemoryStore()}
	body := `{"name":"my-conn"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConnectionDetailHandler_GET_ValueFree(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()
	create := &api.ConnectionsHandler{Store: store}
	create.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/connections", bytes.NewBufferString(`{"provider":"openrouter","fields":{"api_key":"test-key"}}`)))

	h := &api.ConnectionDetailHandler{Store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/connections/openrouter", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	canary.AssertNoLeak(t,
		[]string{canary.Phase10Sentinel},
		canary.JSONResponse(rec.Body.String()),
	)
}

func TestConnectionDetailHandler_RotateField(t *testing.T) {
	t.Parallel()
	h := &api.ConnectionDetailHandler{Store: newAPIMemoryStore()}
	req := httptest.NewRequest(http.MethodPost, "/api/connections/openrouter/fields/api_key/rotate", bytes.NewBufferString(`{"value":"new-key"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestConnectionUpdate_ApprovalPolicy(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()

	// Create the connection first.
	create := &api.ConnectionsHandler{Store: store}
	create.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/api/connections",
			bytes.NewBufferString(`{"provider":"openrouter","fields":{"api_key":"test-key"}}`)),
	)

	// PUT with approval_policy "trust".
	detail := &api.ConnectionDetailHandler{Store: store}
	putReq := httptest.NewRequest(http.MethodPut, "/api/connections/openrouter",
		bytes.NewBufferString(`{"fields":[],"approval_policy":"trust"}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	detail.ServeHTTP(putRec, putReq)
	require.Equal(t, http.StatusOK, putRec.Code)

	// GET /api/connections and verify approval_policy is "trust".
	list := &api.ConnectionsHandler{Store: store}
	getReq := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	getRec := httptest.NewRecorder()
	list.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)

	var body struct {
		Connections []struct {
			Provider       string `json:"provider"`
			ApprovalPolicy string `json:"approval_policy"`
		} `json:"connections"`
	}
	require.NoError(t, json.NewDecoder(getRec.Body).Decode(&body))
	require.Len(t, body.Connections, 1)
	assert.Equal(t, "openrouter", body.Connections[0].Provider)
	assert.Equal(t, "trust", body.Connections[0].ApprovalPolicy)
}

func TestConnectionUpdate_ApprovalPolicy_Invalid(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()

	// Create the connection first.
	create := &api.ConnectionsHandler{Store: store}
	create.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/api/connections",
			bytes.NewBufferString(`{"provider":"openrouter","fields":{"api_key":"test-key"}}`)),
	)

	// PUT with an invalid approval_policy value.
	detail := &api.ConnectionDetailHandler{Store: store}
	putReq := httptest.NewRequest(http.MethodPut, "/api/connections/openrouter",
		bytes.NewBufferString(`{"fields":[],"approval_policy":"always"}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	detail.ServeHTTP(putRec, putReq)
	assert.Equal(t, http.StatusBadRequest, putRec.Code)
}
