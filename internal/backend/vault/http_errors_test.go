package vault_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/vault"
)

type bkVaultReq struct {
	method    string
	path      string
	token     string
	namespace string
	body      string
}

type bkVaultReply struct {
	status int
	body   string
}

// bkVaultServer replies from a "METHOD /path" table and records every request.
type bkVaultServer struct {
	mu      sync.Mutex
	reqs    []bkVaultReq
	replies map[string]bkVaultReply
}

func (s *bkVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	method := r.Method
	if method == http.MethodGet && r.URL.Query().Get("list") == "true" {
		method = "LIST"
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, bkVaultReq{method: method, path: r.URL.Path, token: r.Header.Get("X-Vault-Token"), namespace: r.Header.Get("X-Vault-Namespace"), body: string(raw)})
	rep, ok := s.replies[method+" "+r.URL.Path]
	s.mu.Unlock()
	if !ok {
		rep = bkVaultReply{status: http.StatusNotFound, body: `{"errors":[]}`}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, rep.body)
}

func (s *bkVaultServer) requests() []bkVaultReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bkVaultReq(nil), s.reqs...)
}

func bkVaultHermetic(t *testing.T) {
	t.Helper()
	for _, k := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "VAULT_AGENT_ADDR", "VAULT_CACERT", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY", "VAULT_SKIP_VERIFY"} {
		t.Setenv(k, "")
		require.NoError(t, os.Unsetenv(k))
	}
	t.Setenv("VAULT_MAX_RETRIES", "0")
	t.Setenv("HOME", t.TempDir())
}

func bkVaultStart(t *testing.T, replies map[string]bkVaultReply) (*bkVaultServer, *httptest.Server) {
	t.Helper()
	bkVaultHermetic(t)
	s := &bkVaultServer{replies: replies}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, ts
}

func bkVaultOpen(t *testing.T, ts *httptest.Server, kv int) *vault.VaultBackend {
	t.Helper()
	b, err := vault.Open(vault.Options{Address: ts.URL, Token: "tok-static", KVVersion: kv, HTTPClient: ts.Client()})
	require.NoError(t, err)
	return b
}

const bkVaultDenied = `{"errors":["permission denied"]}`

func TestVault_PermissionDeniedIsNotNotFound(t *testing.T) {
	denied := bkVaultReply{status: http.StatusForbidden, body: bkVaultDenied}
	_, ts := bkVaultStart(t, map[string]bkVaultReply{
		"GET /v1/secret/data/k":     denied,
		"PUT /v1/secret/data/k":     denied,
		"DELETE /v1/secret/data/k":  denied,
		"LIST /v1/secret/metadata":  denied,
		"GET /v1/kv1/k":             denied,
		"PUT /v1/kv1/k":             denied,
		"DELETE /v1/kv1/k":          denied,
		"LIST /v1/kv1/sub":          denied,
		"GET /v1/secret/data/plain": {status: 200, body: `{"data":{"data":{"other":"first-string"},"metadata":{"version":3}}}`},
	})
	ctx := context.Background()
	secret := "value-never-in-errors"

	v2 := bkVaultOpen(t, ts, 2)
	_, _, err := v2.Get(ctx, "k")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), `vault Get "secret/data/k"`)
	assert.Contains(t, err.Error(), "permission denied")

	err = v2.Set(ctx, "k", []byte(secret), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `vault Set "k"`)
	assert.NotContains(t, err.Error(), secret)

	err = v2.Delete(ctx, "k")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), `vault Delete "k"`)

	_, err = v2.List(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault List")

	val, _, err := v2.Get(ctx, "plain")
	require.NoError(t, err)
	assert.Equal(t, []byte("first-string"), val, "falls back to the first string field")

	v1, err := vault.Open(vault.Options{Address: ts.URL, Token: "tok-static", KVVersion: 1, Mount: "kv1", HTTPClient: ts.Client()})
	require.NoError(t, err)

	_, _, err = v1.Get(ctx, "k")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), `vault Get v1 "kv1/k"`)

	err = v1.Set(ctx, "k", []byte(secret), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `vault Set v1 "k"`)
	assert.NotContains(t, err.Error(), secret)

	err = v1.Delete(ctx, "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `vault Delete v1 "k"`)

	_, err = v1.List(ctx, "sub")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `vault List "sub"`)
}

func TestVault_NotFoundMapping(t *testing.T) {
	_, ts := bkVaultStart(t, map[string]bkVaultReply{
		"DELETE /v1/secret/data/gone": {status: http.StatusNotFound, body: `{"errors":[]}`},
	})
	b := bkVaultOpen(t, ts, 2)

	require.ErrorIs(t, b.Delete(context.Background(), "gone"), backend.ErrNotFound)

	entries, err := b.List(context.Background(), "missing")
	require.NoError(t, err, "a 404 on list means an empty folder")
	assert.Empty(t, entries)
}

func TestVault_ListShapes(t *testing.T) {
	_, ts := bkVaultStart(t, map[string]bkVaultReply{
		"LIST /v1/kv1/app":            {status: 200, body: `{"data":{"keys":["db",7,"api/"]}}`},
		"LIST /v1/kv1":                {status: 200, body: `{"data":{"keys":"not-a-list"}}`},
		"LIST /v1/secret/metadata/nd": {status: 200, body: `{}`},
	})
	ctx := context.Background()
	v1, err := vault.Open(vault.Options{Address: ts.URL, Token: "t", KVVersion: 1, Mount: "kv1", HTTPClient: ts.Client()})
	require.NoError(t, err)

	entries, err := v1.List(ctx, "app")
	require.NoError(t, err)
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	assert.Equal(t, []string{"app/db", "app/api/"}, paths, "non-string keys are skipped")

	entries, err = v1.List(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, entries)

	entries, err = bkVaultOpen(t, ts, 2).List(ctx, "nd")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestVaultGetV1_NonStringValueRejected(t *testing.T) {
	_, ts := bkVaultStart(t, map[string]bkVaultReply{
		"GET /v1/kv1/num": {status: 200, body: `{"data":{"value":12}}`},
	})
	b, err := vault.Open(vault.Options{Address: ts.URL, Token: "t", KVVersion: 1, Mount: "kv1", HTTPClient: ts.Client()})
	require.NoError(t, err)
	_, _, err = b.Get(context.Background(), "num")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "value field is not a string")
}

func TestVaultAppRole_NamespaceAndRevokeOnClose(t *testing.T) {
	roleID, secretID := "role-abc", "sid-"+strings.Repeat("z", 10)
	s, ts := bkVaultStart(t, map[string]bkVaultReply{
		"POST /v1/auth/approle/login":     {status: 200, body: `{"auth":{"client_token":"issued-tok"}}`},
		"PUT /v1/auth/token/revoke-self":  {status: 204},
		"POST /v1/auth/token/revoke-self": {status: 204},
		"GET /v1/secret/data/k":           {status: 200, body: `{"data":{"data":{"value":"v"},"metadata":{}}}`},
	})

	b, err := vault.Open(vault.Options{Address: ts.URL, RoleID: roleID, SecretID: secretID, Namespace: "team-a", HTTPClient: ts.Client()})
	require.NoError(t, err)
	assert.Equal(t, "vault:"+ts.URL+"/team-a", b.ID())

	_, _, err = b.Get(context.Background(), "k")
	require.NoError(t, err)
	require.NoError(t, b.Close())

	reqs := s.requests()
	require.GreaterOrEqual(t, len(reqs), 3)

	login := reqs[0]
	assert.Equal(t, "/v1/auth/approle/login", login.path)
	assert.Equal(t, "team-a", login.namespace)
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(login.body), &payload))
	assert.Equal(t, roleID, payload["role_id"])
	assert.Equal(t, secretID, payload["secret_id"])

	assert.Equal(t, "issued-tok", reqs[1].token)
	assert.Equal(t, "team-a", reqs[1].namespace)

	last := reqs[len(reqs)-1]
	assert.Equal(t, "/v1/auth/token/revoke-self", last.path, "Close must revoke the AppRole token")
	assert.Equal(t, "issued-tok", last.token)

	for _, r := range reqs[1:] {
		assert.NotContains(t, r.body, secretID, "secret_id is only sent to the login endpoint")
	}
}

func TestVaultClose_StaticTokenNotRevoked(t *testing.T) {
	s, ts := bkVaultStart(t, nil)
	b := bkVaultOpen(t, ts, 2)
	require.NoError(t, b.Close())
	assert.Empty(t, s.requests(), "a caller-supplied token must never be revoked")
}

func TestVaultAppRole_BadResponses(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"malformed json", `{not json`, "decode response"},
		{"missing token", `{"auth":{}}`, "no client_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ts := bkVaultStart(t, map[string]bkVaultReply{
				"POST /v1/auth/approle/login": {status: 200, body: tc.body},
			})
			secretID := "sid-" + strings.Repeat("y", 10)
			_, err := vault.Open(vault.Options{Address: ts.URL, RoleID: "r", SecretID: secretID, HTTPClient: ts.Client()})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.NotContains(t, err.Error(), secretID)
		})
	}
}

func TestVaultAppRole_ServerUnreachable(t *testing.T) {
	bkVaultHermetic(t)
	ts := httptest.NewServer(http.NotFoundHandler())
	addr := ts.URL
	ts.Close()

	_, err := vault.Open(vault.Options{Address: addr, RoleID: "r", SecretID: "s"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole login request")
}

func TestVaultOpen_InvalidAddress(t *testing.T) {
	bkVaultHermetic(t)
	_, err := vault.Open(vault.Options{Address: "http://bad host:1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault backend: create client")
}

func TestVaultFactory_DecodesSettings(t *testing.T) {
	s, ts := bkVaultStart(t, map[string]bkVaultReply{
		"GET /v1/kv/app/key": {status: 200, body: `{"data":{"value":"from-v1"}}`},
	})
	f, ok := backend.Default.Get("vault")
	require.True(t, ok)

	b, err := f(context.Background(), backend.BackendConfig{Name: "vault", Settings: map[string]any{
		"address": ts.URL, "token": "tok-factory", "mount": "kv", "kv_version": "1", "namespace": "ns1",
	}})
	require.NoError(t, err)
	val, _, err := b.Get(context.Background(), "app/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("from-v1"), val)

	reqs := s.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "tok-factory", reqs[0].token)
	assert.Equal(t, "ns1", reqs[0].namespace)

	b2, err := f(context.Background(), backend.BackendConfig{Name: "vault", Settings: map[string]any{}})
	require.NoError(t, err)
	assert.Equal(t, "vault:http://127.0.0.1:8200", b2.ID(), "defaults to the local dev address")

	_, err = f(context.Background(), backend.BackendConfig{Name: "vault", Settings: map[string]any{"tokn": "typo"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")
}
