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
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// openDoppler is a helper that opens a DopplerBackend against a test server.
func openDoppler(t *testing.T, srv *httptest.Server) *doppler.DopplerBackend {
	t.Helper()
	b, err := doppler.Open(doppler.Options{
		Token:      "dp.st.test",
		Project:    "myapp",
		Config:     "dev",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	return b
}

func TestDopplerName(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	assert.Equal(t, "doppler", b.Name())
}

func TestDopplerID(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	assert.Contains(t, b.ID(), "doppler")
	assert.Contains(t, b.ID(), "myapp")
}

func TestDopplerClose(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	assert.NoError(t, b.Close())
}

func TestDopplerSet(t *testing.T) {
	secrets := map[string]string{}
	srv := newDopplerTestServer(secrets)
	defer srv.Close()
	b := openDoppler(t, srv)

	err := b.Set(context.Background(), "NEW_KEY", []byte("new-value"), backend.Meta{})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "NEW_KEY")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), val)
}

func TestDopplerDelete(t *testing.T) {
	secrets := map[string]string{"DEL_KEY": "del-val"}
	srv := newDopplerTestServer(secrets)
	defer srv.Close()
	b := openDoppler(t, srv)

	err := b.Delete(context.Background(), "DEL_KEY")
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "DEL_KEY")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestDopplerDelete_NotFound(t *testing.T) {
	// A 404 on delete should return ErrNotFound.
	// Override server to return 404 for DELETE.
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	notFoundSrv := httptest.NewServer(mux)
	defer notFoundSrv.Close()

	b2, err := doppler.Open(doppler.Options{
		Token:      "tok",
		Project:    "p",
		Config:     "c",
		BaseURL:    notFoundSrv.URL,
		HTTPClient: notFoundSrv.Client(),
	})
	require.NoError(t, err)
	err = b2.Delete(context.Background(), "MISSING")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestDopplerGet_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secret", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "tok",
		Project:    "p",
		Config:     "c",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	_, _, err = b.Get(context.Background(), "KEY")
	require.Error(t, err)
}

func TestDopplerList_WithPrefix(t *testing.T) {
	secrets := map[string]string{
		"MYAPP_KEY1": "v1",
		"MYAPP_KEY2": "v2",
		"OTHER_KEY":  "v3",
	}
	srv := newDopplerTestServer(secrets)
	defer srv.Close()
	b := openDoppler(t, srv)

	entries, err := b.List(context.Background(), "MYAPP")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, e.Exists)
	}
}

func TestDopplerList_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "tok",
		Project:    "p",
		Config:     "c",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	_, err = b.List(context.Background(), "")
	require.Error(t, err)
}

func TestDopplerSet_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"secrets": map[string]interface{}{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b, err := doppler.Open(doppler.Options{
		Token:      "tok",
		Project:    "p",
		Config:     "c",
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	err = b.Set(context.Background(), "KEY", []byte("val"), backend.Meta{})
	require.Error(t, err)
}

func TestDopplerOpen_MissingToken(t *testing.T) {
	_, err := doppler.Open(doppler.Options{
		Project: "p",
		Config:  "c",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestDopplerOpen_MissingProject(t *testing.T) {
	_, err := doppler.Open(doppler.Options{
		Token:  "tok",
		Config: "c",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

func TestDopplerOpen_MissingConfig(t *testing.T) {
	_, err := doppler.Open(doppler.Options{
		Token:   "tok",
		Project: "p",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config")
}

func TestDopplerGetMeta_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	_, err := b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerSetMeta_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	err := b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerListMeta_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	_, err := b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerGetVersioned_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	_, err := b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerSetVersioned_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	err := b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerDeleteVersioned_NotSupported(t *testing.T) {
	srv := newDopplerTestServer(nil)
	defer srv.Close()
	b := openDoppler(t, srv)
	err := b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestDopplerCapabilities_HasCapList(t *testing.T) {
	b, err := doppler.Open(doppler.Options{
		Token:   "tok",
		Project: "p",
		Config:  "c",
	})
	require.NoError(t, err)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "doppler must report CapList")
}
