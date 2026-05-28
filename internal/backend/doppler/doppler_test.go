package doppler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/doppler"
)

func newDopplerTestServer(secrets map[string]string) *httptest.Server {
	mux := http.NewServeMux()

	// GET /v3/configs/config/secret — single secret
	mux.HandleFunc("/v3/configs/config/secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("name")
		val, ok := secrets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"value": map[string]string{"raw": val},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// GET /v3/configs/config/secrets — list all
	// POST /v3/configs/config/secrets — set
	// DELETE /v3/configs/config/secrets — delete
	mux.HandleFunc("/v3/configs/config/secrets", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list := make(map[string]map[string]string)
			for name, val := range secrets {
				list[name] = map[string]string{"raw": val}
			}
			resp := map[string]interface{}{"secrets": list}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case http.MethodPost:
			var payload struct {
				Secrets map[string]string `json:"secrets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for k, v := range payload.Secrets {
				secrets[k] = v
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})

		case http.MethodDelete:
			var payload struct {
				Secrets []string `json:"secrets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, k := range payload.Secrets {
				delete(secrets, k)
			}
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return httptest.NewServer(mux)
}

func TestDopplerGet(t *testing.T) {
	srv := newDopplerTestServer(map[string]string{"MY_API_KEY": "dop-secret"})
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "dp.st.test",
		Project:    "myapp",
		Config:     "dev",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "MY_API_KEY")
	require.NoError(t, err)
	assert.Equal(t, []byte("dop-secret"), val)
	assert.Equal(t, "doppler", meta.Backend)
}

func TestDopplerGet_NotFound(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "dp.st.test",
		Project:    "myapp",
		Config:     "dev",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "MISSING_KEY")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestDopplerList(t *testing.T) {
	srv := newDopplerTestServer(map[string]string{
		"KEY1": "val1",
		"KEY2": "val2",
	})
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "dp.st.test",
		Project:    "myapp",
		Config:     "dev",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestDopplerCapabilities(t *testing.T) {
	b, err := doppler.Open(doppler.Options{
		Token:   "dp.st.test",
		Project: "myapp",
		Config:  "dev",
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
	assert.True(t, found, "doppler must report CapNetworkedFetch")
}
