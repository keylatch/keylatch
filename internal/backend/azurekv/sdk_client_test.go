package azurekv_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/azurekv"
)

type bkAzureReq struct {
	method string
	path   string
	query  string
	body   string
	auth   string
}

// bkAzureVault answers Key Vault REST calls directly (never with a 401
// challenge), so the SDK never needs to acquire a token from Entra ID.
type bkAzureVault struct {
	mu      sync.Mutex
	reqs    []bkAzureReq
	secrets map[string]string
	baseURL string
	failAll int
}

func (v *bkAzureVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	v.mu.Lock()
	v.reqs = append(v.reqs, bkAzureReq{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(raw), auth: r.Header.Get("Authorization")})
	fail := v.failAll
	v.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if fail != 0 {
		w.WriteHeader(fail)
		_, _ = io.WriteString(w, `{"error":{"code":"Forbidden","message":"simulated"}}`)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":"SecretNotFound","message":"missing"}}`)
	}
	switch {
	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "secrets":
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
			{"id": v.baseURL + "/secrets/app-one"},
			{"id": v.baseURL + "/secrets/zzz"},
		}})
	case r.Method == http.MethodGet && len(parts) >= 2:
		val, ok := v.secrets[parts[1]]
		if !ok {
			notFound()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": val, "id": v.baseURL + "/secrets/" + parts[1] + "/v1"})
	case r.Method == http.MethodPut && len(parts) == 2:
		_ = json.NewEncoder(w).Encode(map[string]any{"id": v.baseURL + "/secrets/" + parts[1] + "/v2"})
	case r.Method == http.MethodDelete && len(parts) == 2:
		if _, ok := v.secrets[parts[1]]; !ok {
			notFound()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": v.baseURL + "/secrets/" + parts[1]})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// bkAzureServe starts a TLS vault and makes the process trust its
// certificate via SSL_CERT_FILE; this only works on Linux and only before the
// system pool is first loaded, which nothing else in this binary does.
func bkAzureServe(t *testing.T, v *bkAzureVault) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("SSL_CERT_FILE trust injection is Linux-only")
	}
	ts := httptest.NewTLSServer(v)
	t.Cleanup(ts.Close)
	v.baseURL = ts.URL

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	require.NoError(t, os.WriteFile(certPath, pemBytes, 0o600))
	t.Setenv("SSL_CERT_FILE", certPath)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	for _, k := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_AUTHORITY_HOST"} {
		t.Setenv(k, "")
	}
	return ts.URL
}

func TestAzureRealClient_CRUDThroughSDK(t *testing.T) {
	v := &bkAzureVault{secrets: map[string]string{"db": "hunter-two"}}
	vaultURL := bkAzureServe(t, v)

	clientSecret := "cs-" + strings.Repeat("q", 12)
	b, err := azurekv.Open(azurekv.Options{
		VaultURL:     vaultURL,
		TenantID:     "00000000-0000-0000-0000-000000000001",
		ClientID:     "00000000-0000-0000-0000-000000000002",
		ClientSecret: clientSecret,
	})
	require.NoError(t, err)
	assert.Equal(t, "azure-kv:127", b.ID())

	ctx := context.Background()
	val, meta, err := b.Get(ctx, "db")
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter-two"), val)
	assert.Equal(t, "db", meta.Path)

	_, _, err = b.Get(ctx, "missing")
	require.ErrorIs(t, err, backend.ErrNotFound)

	require.NoError(t, b.Set(ctx, "newkey", []byte("fresh-value"), backend.Meta{}))
	require.NoError(t, b.Delete(ctx, "db"))
	require.ErrorIs(t, b.Delete(ctx, "nope"), backend.ErrNotFound)

	entries, err := b.List(ctx, "app-")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "app-one", entries[0].Path)

	v.mu.Lock()
	defer v.mu.Unlock()
	var sawPut bool
	for _, r := range v.reqs {
		assert.NotContains(t, r.auth, clientSecret)
		assert.NotContains(t, r.query, clientSecret)
		assert.NotContains(t, r.body, clientSecret)
		if r.method == http.MethodPut && strings.HasSuffix(r.path, "/secrets/newkey") {
			sawPut = true
		}
	}
	assert.True(t, sawPut, "SetSecret must PUT to /secrets/<name>")
}

func TestAzureRealClient_ServiceErrorWrapped(t *testing.T) {
	v := &bkAzureVault{failAll: http.StatusForbidden}
	vaultURL := bkAzureServe(t, v)

	f, ok := backend.Default.Get("azure-kv")
	require.True(t, ok)
	b, err := f(context.Background(), backend.BackendConfig{Name: "azure-kv", Settings: map[string]any{"vault_url": vaultURL}})
	require.NoError(t, err, "default credential chain must construct without network")

	_, _, err = b.Get(context.Background(), "x")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), `azure-kv Get "x"`)

	err = b.Set(context.Background(), "x", []byte("never-echo-me"), backend.Meta{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "never-echo-me")

	_, err = b.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure-kv List")
}
