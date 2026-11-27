package infisical_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/infisical"
)

const bkinLoginPath = "/api/v1/auth/universal-auth/login"

func bkinClientSecret() string { return "cs" + "-" + strings.Repeat("s", 24) }

func bkinAccess() string { return "at" + "-" + strings.Repeat("a", 24) }

func bkinOpen(t *testing.T, baseURL string) *infisical.InfisicalBackend {
	t.Helper()
	b, err := infisical.Open(infisical.Options{
		BaseURL:      baseURL,
		ClientID:     "cid",
		ClientSecret: bkinClientSecret(),
		WorkspaceID:  "ws",
		Environment:  "dev",
	})
	require.NoError(t, err)
	return b
}

// bkinServe answers the login endpoint with a valid token and delegates everything else to h,
// rejecting requests that do not carry that token.
func bkinServe(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bkinLoginPath {
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": bkinAccess()})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+bkinAccess() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func bkinTruncated(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", "64")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{"))
}

func bkinStatus(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

func bkinNoCreds(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), bkinClientSecret())
	assert.NotContains(t, err.Error(), bkinAccess())
}

type bkinRoundTrip func(*http.Request) (*http.Response, error)

func (f bkinRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInfisicalOpen_InvalidBaseURL(t *testing.T) {
	_, err := infisical.Open(infisical.Options{BaseURL: "http://bad\x7fhost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse base_url")
}

func TestInfisicalOpen_Defaults(t *testing.T) {
	var hosts []string
	var secretPath string
	client := &http.Client{Transport: bkinRoundTrip(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Scheme+"://"+r.URL.Host)
		body := `{"accessToken":"` + bkinAccess() + `"}`
		if r.URL.Path != bkinLoginPath {
			secretPath = r.URL.Query().Get("secretPath")
			body = `{"secret":{"secretValue":"v"}}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	b, err := infisical.Open(infisical.Options{ClientID: "c", ClientSecret: bkinClientSecret(), WorkspaceID: "ws", HTTPClient: client})
	require.NoError(t, err)
	assert.Equal(t, "infisical:app.infisical.com/ws", b.ID())

	val, _, err := b.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "v", string(val))
	assert.Equal(t, []string{"https://app.infisical.com", "https://app.infisical.com"}, hosts)
	assert.Equal(t, "/", secretPath)
}

func TestInfisicalLogin_Failures(t *testing.T) {
	cases := []struct {
		name  string
		login http.HandlerFunc
		want  string
	}{
		{"rejected credentials", bkinStatus(http.StatusUnauthorized), "infisical login: HTTP 401"},
		{"server down", bkinStatus(http.StatusServiceUnavailable), "infisical login: HTTP 503"},
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("nope")) }, "decode response"},
		{"truncated", bkinTruncated, "infisical login: read response"},
		{"empty token", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"accessToken":""}`)) }, "no access token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var secretCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == bkinLoginPath {
					var body map[string]string
					assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					assert.Equal(t, bkinClientSecret(), body["clientSecret"])
					tc.login(w, r)
					return
				}
				secretCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			b := bkinOpen(t, srv.URL)
			ctx := context.Background()

			_, _, err := b.Get(ctx, "K")
			bkinNoCreds(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotErrorIs(t, err, backend.ErrNotFound)

			err = b.Set(ctx, "K", []byte("v"), backend.Meta{})
			bkinNoCreds(t, err)
			assert.Contains(t, err.Error(), tc.want)

			err = b.Delete(ctx, "K")
			bkinNoCreds(t, err)

			_, err = b.List(ctx, "")
			bkinNoCreds(t, err)
			assert.Contains(t, err.Error(), tc.want)

			assert.Zero(t, secretCalls.Load(), "no secret request may be sent without a token")
		})
	}
}

func TestInfisicalTokenRefresh_LoginFailsOnRetry(t *testing.T) {
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bkinLoginPath {
			if logins.Add(1) > 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": bkinAccess()})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, _, err := bkinOpen(t, srv.URL).Get(context.Background(), "K")
	bkinNoCreds(t, err)
	assert.Contains(t, err.Error(), "token refresh: infisical login: HTTP 403")
	assert.Equal(t, int32(2), logins.Load())
}

func TestInfisicalTokenRefresh_RetriesPostWithBody(t *testing.T) {
	var logins, posts atomic.Int32
	secret := "val-" + strings.Repeat("w", 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bkinLoginPath {
			n := logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": bkinAccess() + string(rune('0'+n))})
			return
		}
		posts.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+bkinAccess()+"2" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, secret, body["secretValue"])
		assert.Equal(t, "/", body["secretPath"])
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	require.NoError(t, bkinOpen(t, srv.URL).Set(context.Background(), "K", []byte(secret), backend.Meta{}))
	assert.Equal(t, int32(2), logins.Load())
	assert.Equal(t, int32(2), posts.Load())
}

func TestInfisicalGet_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"server error", bkinStatus(http.StatusInternalServerError), "HTTP 500"},
		{"forbidden", bkinStatus(http.StatusForbidden), "HTTP 403"},
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[")) }, "decode response"},
		{"truncated", bkinTruncated, "read response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkinServe(t, tc.h)
			_, _, err := bkinOpen(t, srv.URL).Get(context.Background(), "K")
			bkinNoCreds(t, err)
			assert.False(t, errors.Is(err, backend.ErrNotFound))
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestInfisicalList_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"server error", bkinStatus(http.StatusBadGateway), "HTTP 502"},
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{]")) }, "decode response"},
		{"truncated", bkinTruncated, "read response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkinServe(t, tc.h)
			_, err := bkinOpen(t, srv.URL).List(context.Background(), "")
			bkinNoCreds(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestInfisicalList_PrefixFilter(t *testing.T) {
	srv := bkinServe(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"secrets":[{"secretKey":"APP_A"},{"secretKey":"DB_B"},{"secretKey":"APP_C"}]}`))
	})
	entries, err := bkinOpen(t, srv.URL).List(context.Background(), "APP_")
	require.NoError(t, err)
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
		assert.Equal(t, "infisical", e.Backend)
	}
	assert.Equal(t, []string{"APP_A", "APP_C"}, paths)
}

func TestInfisicalSetDelete_StatusErrors(t *testing.T) {
	secret := "val-" + strings.Repeat("e", 10)
	srv := bkinServe(t, bkinStatus(http.StatusInternalServerError))
	b := bkinOpen(t, srv.URL)

	err := b.Set(context.Background(), "K", []byte(secret), backend.Meta{})
	bkinNoCreds(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
	assert.NotContains(t, err.Error(), secret)

	err = b.Delete(context.Background(), "K")
	bkinNoCreds(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), "HTTP 500")

	ok := bkinServe(t, bkinStatus(http.StatusNoContent))
	require.NoError(t, bkinOpen(t, ok.URL).Delete(context.Background(), "K"))
}

func TestInfisicalGet_PathEscapesName(t *testing.T) {
	srv := bkinServe(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v3/secrets/raw/a%2F..%2Fb", r.URL.EscapedPath())
		_, _ = w.Write([]byte(`{"secret":{"secretValue":"x"}}`))
	})
	val, _, err := bkinOpen(t, srv.URL).Get(context.Background(), "a/../b")
	require.NoError(t, err)
	assert.Equal(t, "x", string(val))
}
