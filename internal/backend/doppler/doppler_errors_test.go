package doppler_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/doppler"
)

func bkdpToken() string { return "dp" + "-" + strings.Repeat("k", 24) }

func bkdpOpen(t *testing.T, baseURL string) *doppler.DopplerBackend {
	t.Helper()
	b, err := doppler.Open(doppler.Options{
		Token:   bkdpToken(),
		Project: "proj one",
		Config:  "dev&x",
		BaseURL: baseURL,
	})
	require.NoError(t, err)
	return b
}

func bkdpServe(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bkdpToken() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func bkdpTruncated(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", "64")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{"))
}

func bkdpStatus(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

func bkdpNoToken(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), bkdpToken())
}

type bkdpRoundTrip func(*http.Request) (*http.Response, error)

func (f bkdpRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDopplerFactory_Registered(t *testing.T) {
	f, ok := backend.Default.Get("doppler")
	require.True(t, ok)

	b, err := f(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{
		"token":   bkdpToken(),
		"project": "p",
		"config":  "c",
		"env":     func(string) string { return "" },
	}})
	require.NoError(t, err)
	assert.Equal(t, "doppler:p/c", b.ID())

	_, err = f(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"nope": "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")

	_, err = f(context.Background(), backend.BackendConfig{Settings: map[string]interface{}{"project": "p", "config": "c"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

func TestDopplerOpen_DefaultsToPublicAPI(t *testing.T) {
	var gotHost, gotScheme string
	client := &http.Client{Transport: bkdpRoundTrip(func(r *http.Request) (*http.Response, error) {
		gotHost, gotScheme = r.URL.Host, r.URL.Scheme
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"value":{"raw":"v"}}`)),
			Header:     http.Header{},
			Request:    r,
		}, nil
	})}
	b, err := doppler.Open(doppler.Options{Token: bkdpToken(), Project: "p", Config: "c", HTTPClient: client})
	require.NoError(t, err)
	val, _, err := b.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "v", string(val))
	assert.Equal(t, "api.doppler.com", gotHost)
	assert.Equal(t, "https", gotScheme)
}

func TestDopplerGet_EscapesQueryAndReturnsRaw(t *testing.T) {
	srv := bkdpServe(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		assert.Equal(t, "proj one", q.Get("project"))
		assert.Equal(t, "dev&x", q.Get("config"))
		assert.Equal(t, "A&B", q.Get("name"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		_ = json.NewEncoder(w).Encode(map[string]any{"value": map[string]string{"raw": "the-value"}})
	})
	val, m, err := bkdpOpen(t, srv.URL).Get(context.Background(), "A&B")
	require.NoError(t, err)
	assert.Equal(t, "the-value", string(val))
	assert.Equal(t, "A&B", m.Path)
	assert.Equal(t, "doppler", m.Backend)
}

func TestDopplerGet_ErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		h        http.HandlerFunc
		want     string
		notFound bool
	}{
		{"not found", bkdpStatus(http.StatusNotFound), "K", true},
		{"auth failure", bkdpStatus(http.StatusUnauthorized), "HTTP 401", false},
		{"unavailable", bkdpStatus(http.StatusServiceUnavailable), "HTTP 503", false},
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, "decode response", false},
		{"truncated", bkdpTruncated, "read response", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkdpServe(t, tc.h)
			_, _, err := bkdpOpen(t, srv.URL).Get(context.Background(), "K")
			bkdpNoToken(t, err)
			assert.Equal(t, tc.notFound, errors.Is(err, backend.ErrNotFound), "got %v", err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestDopplerList_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[")) }, "decode response"},
		{"truncated", bkdpTruncated, "read response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkdpServe(t, tc.h)
			_, err := bkdpOpen(t, srv.URL).List(context.Background(), "")
			bkdpNoToken(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestDopplerList_ReturnsNamesOnly(t *testing.T) {
	srv := bkdpServe(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"secrets":{"APP_KEY":{"raw":"hidden-1"},"DB_URL":{"raw":"hidden-2"}}}`))
	})
	entries, err := bkdpOpen(t, srv.URL).List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, e.Exists)
		assert.NotContains(t, e.Path, "hidden")
	}
}

func TestDopplerDelete_ErrorMapping(t *testing.T) {
	srv := bkdpServe(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		var body struct {
			Project string   `json:"project"`
			Config  string   `json:"config"`
			Secrets []string `json:"secrets"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, []string{"K"}, body.Secrets)
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := bkdpOpen(t, srv.URL).Delete(context.Background(), "K")
	bkdpNoToken(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), "HTTP 500")

	srv204 := bkdpServe(t, bkdpStatus(http.StatusNoContent))
	require.NoError(t, bkdpOpen(t, srv204.URL).Delete(context.Background(), "K"))
}

func TestDopplerSet_ValueOnlyInBody(t *testing.T) {
	secret := "sv-" + strings.Repeat("q", 16)
	srv := bkdpServe(t, func(w http.ResponseWriter, r *http.Request) {
		assert.NotContains(t, r.URL.String(), secret)
		var body struct {
			Secrets map[string]string `json:"secrets"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, secret, body.Secrets["K"])
		w.WriteHeader(http.StatusCreated)
	})
	require.NoError(t, bkdpOpen(t, srv.URL).Set(context.Background(), "K", []byte(secret), backend.Meta{}))

	bad := bkdpServe(t, bkdpStatus(http.StatusBadRequest))
	err := bkdpOpen(t, bad.URL).Set(context.Background(), "K", []byte(secret), backend.Meta{})
	bkdpNoToken(t, err)
	assert.NotContains(t, err.Error(), secret)
}

func TestDopplerTransportErrors(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	b := bkdpOpen(t, u)
	ctx := context.Background()

	_, _, err := b.Get(ctx, "K")
	bkdpNoToken(t, err)
	err = b.Set(ctx, "K", []byte("v"), backend.Meta{})
	bkdpNoToken(t, err)
	err = b.Delete(ctx, "K")
	bkdpNoToken(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	_, err = b.List(ctx, "")
	bkdpNoToken(t, err)
}

func TestDopplerInvalidBaseURLFailsBeforeSending(t *testing.T) {
	b := bkdpOpen(t, "http://bad\x7fhost")
	ctx := context.Background()

	_, _, err := b.Get(ctx, "K")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
	err = b.Set(ctx, "K", []byte("v"), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
	err = b.Delete(ctx, "K")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
	_, err = b.List(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
}
