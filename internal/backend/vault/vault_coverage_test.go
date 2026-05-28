package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// vaultTestServer builds an httptest.Server with a simple in-memory KV store.
// It handles KV v2 paths: data/<path> for GET/POST, metadata/<prefix> for LIST.
func vaultTestServer() (srv *httptest.Server, data map[string]string) {
	data = make(map[string]string)
	mux := http.NewServeMux()

	// Catch-all: handles GET/POST/DELETE on /v1/secret/*
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case len(path) > len("/v1/secret/data/") && path[:len("/v1/secret/data/")] == "/v1/secret/data/":
			key := path[len("/v1/secret/data/"):]
			switch r.Method {
			case http.MethodGet:
				val, ok := data[key]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"errors":[]}`))
					return
				}
				_, _ = w.Write(kvV2Response(val))
			case http.MethodPost, http.MethodPut:
				var body struct {
					Data map[string]interface{} `json:"data"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if v, ok := body.Data["value"].(string); ok {
					data[key] = v
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"version":1}}`))
			case http.MethodDelete:
				delete(data, key)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}

		case len(path) > len("/v1/secret/metadata/") && path[:len("/v1/secret/metadata/")] == "/v1/secret/metadata/":
			prefix := path[len("/v1/secret/metadata/"):]
			var keys []interface{}
			for k := range data {
				if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
					shortKey := k
					if prefix != "" {
						shortKey = k[len(prefix):]
					}
					keys = append(keys, shortKey)
				}
			}
			resp := map[string]interface{}{"data": map[string]interface{}{"keys": keys}}
			raw, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)

		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	srv = httptest.NewServer(mux)
	return srv, data
}

func openVault(t *testing.T, srv *httptest.Server) *vault.VaultBackend {
	t.Helper()
	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	return b
}

func TestVaultName(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	assert.Equal(t, "vault", b.Name())
}

func TestVaultID_WithNamespace(t *testing.T) {
	b, err := vault.Open(vault.Options{
		Address:   "http://127.0.0.1:18200",
		Token:     "root",
		Namespace: "ns1",
	})
	require.NoError(t, err)
	id := b.ID()
	assert.Contains(t, id, "vault")
	assert.Contains(t, id, "ns1")
}

func TestVaultID_WithoutNamespace(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	id := b.ID()
	assert.Contains(t, id, "vault")
	// Should not have a namespace segment — the format is "vault:<address>" with no extra slash.
	assert.NotContains(t, id, "ns")
}

func TestVaultClose_NoToken(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	// Close with no appRoleToken should be a no-op.
	assert.NoError(t, b.Close())
}

func TestVaultSet_KVv2(t *testing.T) {
	srv, _ := vaultTestServer()
	defer srv.Close()
	b := openVault(t, srv)

	err := b.Set(context.Background(), "myapp/newkey", []byte("newval"), backend.Meta{})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp/newkey")
	require.NoError(t, err)
	assert.Equal(t, []byte("newval"), val)
	assert.Equal(t, "vault", meta.Backend)
}

func TestVaultSet_KVv1(t *testing.T) {
	data := make(map[string]string)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/v1/secret/"):]
		switch r.Method {
		case http.MethodPut:
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["value"].(string); ok {
				data[path] = v
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case http.MethodGet:
			val, ok := data[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_, _ = w.Write(kvV1Response(val))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  1,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	err = b.Set(context.Background(), "mykey", []byte("myval"), backend.Meta{})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "mykey")
	require.NoError(t, err)
	assert.Equal(t, []byte("myval"), val)
}

func TestVaultDelete_KVv2(t *testing.T) {
	data := make(map[string]string)
	data["myapp/delkey"] = "todelete"

	mux := http.NewServeMux()
	deleted := false
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			path := r.URL.Path[len("/v1/secret/data/"):]
			if deleted {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			val, ok := data[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_, _ = w.Write(kvV2Response(val))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "myapp/delkey")
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestVaultDelete_KVv1(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  1,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "mykey")
	require.NoError(t, err)
}

func TestVaultDelete_NotFound_KVv1(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  1,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "mykey")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestVaultList_KVv2(t *testing.T) {
	data := map[string]string{
		"myapp/key1": "val1",
		"myapp/key2": "val2",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Path[len("/v1/secret/metadata/"):]
		var keys []interface{}
		for k := range data {
			if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
				keys = append(keys, k)
			}
		}
		resp := map[string]interface{}{"data": map[string]interface{}{"keys": keys}}
		raw, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "myapp")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, e.Exists)
	}
}

func TestVaultList_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Nil(t, entries)
}

func TestVaultGetMeta_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	_, err = b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultSetMeta_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	err = b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultListMeta_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	_, err = b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultGetVersioned_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	_, err = b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultSetVersioned_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	err = b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultDeleteVersioned_NotSupported(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	err = b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestVaultCapabilities_HasCapList(t *testing.T) {
	b, err := vault.Open(vault.Options{Address: "http://127.0.0.1:18200", Token: "root"})
	require.NoError(t, err)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "vault must report CapList")
}

func TestVaultGetV1_NilSecret(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/", func(w http.ResponseWriter, r *http.Request) {
		// Return an empty (nil data) response.
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  1,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "mykey")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestVaultGet_NoStringValue(t *testing.T) {
	// Return a secret with no string "value" field.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"not_value": 42, // integer, no string
					},
					"metadata": map[string]interface{}{"version": 1},
				},
			}
			raw, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "myapp/nostring")
	require.Error(t, err)
}

func TestVaultAppRoleLogin_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := vault.Open(vault.Options{
		Address:    srv.URL,
		RoleID:     "bad-role",
		SecretID:   "bad-secret",
		Mount:      "secret",
		HTTPClient: srv.Client(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AppRole login")
}
