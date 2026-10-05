package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errMxStore = errors.New("store unavailable")

// mxFlakyStore wraps the in-memory store and fails selected operations.
type mxFlakyStore struct {
	*apiMemoryStore
	failSet    func(path string) bool
	failGet    func(path string) bool
	failDelete bool
}

func (s *mxFlakyStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if s.failGet != nil && s.failGet(path) {
		return nil, backend.Meta{}, errMxStore
	}
	return s.apiMemoryStore.Get(ctx, path)
}

func (s *mxFlakyStore) Set(ctx context.Context, path string, v []byte, m backend.Meta) error {
	if s.failSet != nil && s.failSet(path) {
		return errMxStore
	}
	return s.apiMemoryStore.Set(ctx, path, v, m)
}

func (s *mxFlakyStore) Delete(ctx context.Context, path string) error {
	if s.failDelete {
		return errMxStore
	}
	return s.apiMemoryStore.Delete(ctx, path)
}

func mxSuffix(suffix string) func(string) bool {
	return func(p string) bool { return strings.HasSuffix(p, suffix) }
}

func mxDo(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mxSeedOpenRouter(t *testing.T, store *apiMemoryStore) {
	t.Helper()
	rec := mxDo(&api.ConnectionsHandler{Store: store}, http.MethodPost, "/api/connections", `{"provider":"openrouter","fields":{"api_key":"seed-value"}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestConnectionsCreate_RequestErrors(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	rec := mxDo(&api.ConnectionsHandler{}, http.MethodPost, "/api/connections", `{"provider":"openrouter"}`)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	h := &api.ConnectionsHandler{Store: newAPIMemoryStore()}
	cases := map[string]struct {
		body string
		want int
	}{
		"malformed json":   {"{", http.StatusBadRequest},
		"bad fields array": {`{"provider":"openrouter","fields":[1,2]}`, http.StatusBadRequest},
		"bad fields map":   {`{"provider":"openrouter","fields":{"api_key":7}}`, http.StatusBadRequest},
		"unknown provider": {`{"provider":"no-such-provider-xyz","fields":{"api_key":"v"}}`, http.StatusInternalServerError},
		"required missing": {`{"provider":"openrouter","fields":"   "}`, http.StatusInternalServerError},
	}
	for name, tc := range cases {
		rec := mxDo(h, http.MethodPost, "/api/connections", tc.body)
		assert.Equal(t, tc.want, rec.Code, name+": "+rec.Body.String())
	}

	rec = mxDo(h, http.MethodPatch, "/api/connections", "")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestConnectionsCreate_DuplicateIsConflict(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()
	mxSeedOpenRouter(t, store)
	rec := mxDo(&api.ConnectionsHandler{Store: store}, http.MethodPost, "/api/connections",
		`{"provider":"openrouter","name":"api_key","value":"second"}`)
	assert.Equal(t, http.StatusConflict, rec.Code)
	// The original secret must not be overwritten by the rejected request.
	v, _, err := store.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "seed-value", string(v))
}

func TestConnectionsCreate_LegacyNameValue(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()
	rec := mxDo(&api.ConnectionsHandler{Store: store}, http.MethodPost, "/api/connections",
		`{"provider":"openrouter","name":"api_key","value":"legacy-value"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "legacy-value")
	v, _, err := store.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "legacy-value", string(v))
}

func TestConnectionsCreate_FieldModesSaveFailureWarns(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := &mxFlakyStore{apiMemoryStore: newAPIMemoryStore(), failSet: mxSuffix("/fieldmodes")}
	rec := mxDo(&api.ConnectionsHandler{Store: store}, http.MethodPost, "/api/connections",
		`{"provider":"openrouter","fields":[{"name":"api_key","value":"v1"}]}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var body struct {
		ID       string   `json:"id"`
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "default/openrouter/default", body.ID)
	require.Len(t, body.Warnings, 1)
	assert.Contains(t, body.Warnings[0], "field modes could not be saved")
}

func TestConnectionsList_CorruptSidecarsFallBackToDefaults(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()
	mxSeedOpenRouter(t, store)
	ctx := context.Background()
	require.NoError(t, store.Set(ctx, "default/ai/openrouter/fieldmodes", []byte("{bad"), backend.Meta{}))
	require.NoError(t, store.Set(ctx, "default/ai/openrouter/policy", []byte("{bad"), backend.Meta{}))

	rec := mxDo(&api.ConnectionsHandler{Store: store}, http.MethodGet, "/api/connections", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Connections []struct {
			Name           string                `json:"name"`
			ApprovalPolicy string                `json:"approval_policy"`
			Fields         []api.ConnectionField `json:"fields"`
			CreatedAt      string                `json:"created_at"`
		} `json:"connections"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Len(t, body.Connections, 1)
	c := body.Connections[0]
	assert.Equal(t, "openrouter", c.Name)
	assert.Empty(t, c.ApprovalPolicy)
	assert.NotEmpty(t, c.CreatedAt)
	for _, f := range c.Fields {
		assert.Equal(t, api.FieldModeDirect, f.Mode)
	}
}

func TestConnectionDetail_GetErrors(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	rec := mxDo(&api.ConnectionDetailHandler{}, http.MethodGet, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	store := newAPIMemoryStore()
	rec = mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodGet, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	require.NoError(t, store.Set(context.Background(), "default/ai/openrouter/meta", []byte("not json"), backend.Meta{}))
	rec = mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodGet, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	rec = mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPatch, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestConnectionDetail_UpdateErrors(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	rec := mxDo(&api.ConnectionDetailHandler{}, http.MethodPut, "/api/connections/openrouter", "{}")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	rec = mxDo(&api.ConnectionDetailHandler{Store: newAPIMemoryStore()}, http.MethodPut, "/api/connections/openrouter", "{}")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	flaky := &mxFlakyStore{apiMemoryStore: newAPIMemoryStore(), failGet: mxSuffix("/meta")}
	rec = mxDo(&api.ConnectionDetailHandler{Store: flaky}, http.MethodPut, "/api/connections/openrouter", "{}")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	base := newAPIMemoryStore()
	mxSeedOpenRouter(t, base)
	rec = mxDo(&api.ConnectionDetailHandler{Store: base}, http.MethodPut, "/api/connections/openrouter", "{nope")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConnectionDetail_UpdateWritesDirectValue(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	store := newAPIMemoryStore()
	mxSeedOpenRouter(t, store)

	rec := mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPut, "/api/connections/openrouter",
		`{"fields":[{"name":"api_key","mode":"direct","value":"rotated-value"}],"approval_policy":"prompt"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "rotated-value")

	ctx := context.Background()
	v, _, err := store.Get(ctx, "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "rotated-value", string(v))
	p, _, err := store.Get(ctx, "default/ai/openrouter/policy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"approval_policy":"prompt"}`, string(p))
}

func TestConnectionDetail_UpdateStoreFailures(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	cases := map[string]struct {
		failOn  string
		body    string
		wantMsg string
	}{
		"field modes": {"/fieldmodes", `{"fields":[{"name":"api_key","mode":"direct","value":"x"}]}`, "could not save field metadata"},
		"secret":      {"/api_key", `{"fields":[{"name":"api_key","mode":"direct","value":"x"}]}`, "store error"},
		"policy":      {"/policy", `{"fields":[],"approval_policy":"trust"}`, "could not save approval policy"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mem := newAPIMemoryStore()
			mxSeedOpenRouter(t, mem)
			store := &mxFlakyStore{apiMemoryStore: mem, failSet: mxSuffix(tc.failOn)}
			rec := mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPut, "/api/connections/openrouter", tc.body)
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.wantMsg)
		})
	}

	// A failed metadata write must leave the stored secret untouched.
	mem := newAPIMemoryStore()
	mxSeedOpenRouter(t, mem)
	store := &mxFlakyStore{apiMemoryStore: mem, failSet: mxSuffix("/fieldmodes")}
	mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPut, "/api/connections/openrouter",
		`{"fields":[{"name":"api_key","mode":"direct","value":"should-not-land"}]}`)
	v, _, err := mem.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "seed-value", string(v))
}

func TestConnectionDetail_DeleteAndRotateEdges(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	rec := mxDo(&api.ConnectionDetailHandler{}, http.MethodDelete, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Deleting a known provider with nothing stored is idempotent.
	rec = mxDo(&api.ConnectionDetailHandler{Store: newAPIMemoryStore()}, http.MethodDelete, "/api/connections/openrouter", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)

	rec = mxDo(&api.ConnectionDetailHandler{Store: newAPIMemoryStore()}, http.MethodDelete, "/api/connections/no-such-provider-xyz", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = mxDo(&api.ConnectionDetailHandler{}, http.MethodPost, "/api/connections/openrouter/fields/api_key/rotate", `{"value":"v"}`)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	store := newAPIMemoryStore()
	rec = mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPost, "/api/connections/openrouter/fields/api_key/rotate", `{}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "new field value is required")

	rec = mxDo(&api.ConnectionDetailHandler{Store: store}, http.MethodPost, "/api/connections/openrouter/fields/api_key/rotate", `{"value":"fresh-value"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "fresh-value")
	v, _, err := store.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "fresh-value", string(v))
}

func TestConnectionDetail_TestSuffixRoutesToRuntimeTester(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	rec := mxDo(&api.ConnectionDetailHandler{Store: newAPIMemoryStore()}, http.MethodPost, "/api/connections/openrouter/test", `{}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "missing")
}

func TestClearConnections_Edges(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()

	rec := mxDo(&api.ClearConnectionsHandler{}, http.MethodGet, "/api/connections/clear", "")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	rec = mxDo(&api.ClearConnectionsHandler{}, http.MethodPost, "/api/connections/clear", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"cleared","count":0}`, rec.Body.String())

	mem := newAPIMemoryStore()
	mxSeedOpenRouter(t, mem)
	rec = mxDo(&api.ClearConnectionsHandler{Store: &mxFlakyStore{apiMemoryStore: mem, failDelete: true}}, http.MethodPost, "/api/connections/clear", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "openrouter")
}

func TestRuntimeTestHandler_Edges(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	cases := []struct {
		name   string
		h      *api.RuntimeTestHandler
		method string
		path   string
		body   string
		want   int
	}{
		{"get rejected", &api.RuntimeTestHandler{}, http.MethodGet, "/api/connections/openrouter/test", "", http.StatusMethodNotAllowed},
		{"bad body", &api.RuntimeTestHandler{}, http.MethodPost, "/api/connections/openrouter/test", "{", http.StatusBadRequest},
		{"no connection", &api.RuntimeTestHandler{}, http.MethodPost, "/api/connections//test", "{}", http.StatusBadRequest},
		{"no store", &api.RuntimeTestHandler{}, http.MethodPost, "/api/connections/openrouter/test", "{}", http.StatusServiceUnavailable},
		{"store failure", &api.RuntimeTestHandler{Store: &mxFlakyStore{apiMemoryStore: newAPIMemoryStore(), failGet: func(string) bool { return true }}},
			http.MethodPost, "/api/connections/openrouter/test", "{}", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		rec := mxDo(tc.h, tc.method, tc.path, tc.body)
		assert.Equal(t, tc.want, rec.Code, tc.name)
	}
}
