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
)

// kvV2Response returns a synthetic KV v2 secret response body.
func kvV2Response(value string) []byte {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"data": map[string]interface{}{
				"value": value,
			},
			"metadata": map[string]interface{}{
				"version": 1,
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// kvV1Response returns a synthetic KV v1 secret response body.
func kvV1Response(value string) []byte {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"value": value,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestVaultGet_KVv2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/myapp/key":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(kvV2Response("s3cr3t"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), val)
	assert.Equal(t, "vault", meta.Backend)
}

func TestVaultGet_KVv1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/myapp/key":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(kvV1Response("v1secret"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  1,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "myapp/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("v1secret"), val)
}

func TestVaultGet_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}))
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		Token:      "root",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "missing/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestVaultAppRoleLogin(t *testing.T) {
	loginCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			loginCalled = true
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "approle-token",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			raw, _ := json.Marshal(resp)
			_, _ = w.Write(raw)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/myapp/key":
			// Verify the approle token was set.
			assert.Equal(t, "approle-token", r.Header.Get("X-Vault-Token"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(kvV2Response("approle-secret"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	defer srv.Close()

	b, err := vault.Open(vault.Options{
		Address:    srv.URL,
		RoleID:     "my-role",
		SecretID:   "my-secret",
		Mount:      "secret",
		KVVersion:  2,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	assert.True(t, loginCalled, "AppRole login endpoint should have been called")

	val, _, err := b.Get(context.Background(), "myapp/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("approle-secret"), val)
}

func TestVaultCapabilities(t *testing.T) {
	b, err := vault.Open(vault.Options{
		Address: "http://127.0.0.1:18200",
		Token:   "root",
	})
	require.NoError(t, err)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapNetworkedFetch {
			found = true
			break
		}
	}
	assert.True(t, found, "vault backend must report CapNetworkedFetch")
}
