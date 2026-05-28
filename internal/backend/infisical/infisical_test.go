package infisical_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/infisical"
)

func newInfisicalTestServer(secrets map[string]string) *httptest.Server {
	mux := http.NewServeMux()

	// Universal Auth login
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "test-token"})
	})

	// GET /api/v3/secrets/raw/<name> — single secret
	mux.HandleFunc("/api/v3/secrets/raw/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[len("/api/v3/secrets/raw/"):]
		switch r.Method {
		case http.MethodGet:
			val, ok := secrets[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"secret": map[string]string{
					"secretKey":   name,
					"secretValue": val,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case http.MethodPost:
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			secrets[name] = payload["secretValue"]
			w.WriteHeader(http.StatusOK)

		case http.MethodDelete:
			if _, ok := secrets[name]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(secrets, name)
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// GET /api/v3/secrets/raw — list all
	mux.HandleFunc("/api/v3/secrets/raw", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		type secretEntry struct {
			SecretKey string `json:"secretKey"`
		}
		var list []secretEntry
		for k := range secrets {
			list = append(list, secretEntry{SecretKey: k})
		}
		resp := map[string]interface{}{"secrets": list}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func TestInfisicalGet(t *testing.T) {
	srv := newInfisicalTestServer(map[string]string{"MY_SECRET": "inf-value"})
	defer srv.Close()

	b, err := infisical.Open(infisical.Options{
		BaseURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
		SecretPath:   "/",
		HTTPClient:   srv.Client(),
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "MY_SECRET")
	require.NoError(t, err)
	assert.Equal(t, []byte("inf-value"), val)
	assert.Equal(t, "infisical", meta.Backend)
}

func TestInfisicalGet_NotFound(t *testing.T) {
	srv := newInfisicalTestServer(nil)
	defer srv.Close()

	b, err := infisical.Open(infisical.Options{
		BaseURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
		HTTPClient:   srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "MISSING")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestInfisicalTokenRefresh(t *testing.T) {
	// Simulate a server that returns 401 on first request, then succeeds after re-login.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "new-token"})
		case "/api/v3/secrets/raw/MY_KEY":
			callCount++
			if callCount == 1 {
				// First call: return 401 to trigger refresh.
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Second call: return the secret.
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"secret": map[string]string{
					"secretKey":   "MY_KEY",
					"secretValue": "refreshed-val",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	b, err := infisical.Open(infisical.Options{
		BaseURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
		HTTPClient:   srv.Client(),
	})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "MY_KEY")
	require.NoError(t, err)
	assert.Equal(t, []byte("refreshed-val"), val)
}

func TestInfisicalList(t *testing.T) {
	srv := newInfisicalTestServer(map[string]string{
		"KEY1": "val1",
		"KEY2": "val2",
		"KEY3": "val3",
	})
	defer srv.Close()

	b, err := infisical.Open(infisical.Options{
		BaseURL:      srv.URL,
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
		HTTPClient:   srv.Client(),
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestInfisicalCapabilities(t *testing.T) {
	b, err := infisical.Open(infisical.Options{
		BaseURL:      "https://app.infisical.com",
		ClientID:     "cid",
		ClientSecret: "csecret",
		WorkspaceID:  "ws-123",
		Environment:  "dev",
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
	assert.True(t, found, "infisical must report CapNetworkedFetch")
}
