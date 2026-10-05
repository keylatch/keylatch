package opconnect_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/opconnect"
)

const bkocVault = "vault-1"

func bkocToken() string { return "conn" + "-" + strings.Repeat("t", 24) }

func bkocOpen(t *testing.T, srvURL, vaultID string) *opconnect.OPConnectBackend {
	t.Helper()
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: srvURL,
		Token:      bkocToken(),
		VaultID:    vaultID,
	})
	require.NoError(t, err)
	return b
}

// bkocServe starts a server whose handler also verifies the bearer token on every request.
func bkocServe(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+bkocToken() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func bkocTruncated(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "64")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("[{"))
}

func bkocDropConn(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("response writer does not support hijacking")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
}

func bkocDeadURL() string {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

func bkocNoToken(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), bkocToken())
}

func TestOPConnectFactory_RefusedInThisRelease(t *testing.T) {
	f, ok := backend.Default.Get("op-connect")
	require.True(t, ok)
	_, err := f(context.Background(), backend.BackendConfig{Name: "op-connect", Settings: map[string]interface{}{
		"connect_url": "http://connect.example:8080",
		"token":       bkocToken(),
		"vault_id":    bkocVault,
	}})
	assert.ErrorIs(t, err, backend.ErrUnavailable)
	bkocNoToken(t, err)
}

func TestOPConnectOpen_IDAndRequiredSettings(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{ConnectURL: "http://connect.example:8080", Token: bkocToken(), VaultID: bkocVault})
	require.NoError(t, err)
	assert.Equal(t, "op-connect:connect.example:8080/"+bkocVault, b.ID())

	_, err = opconnect.Open(opconnect.Options{Token: bkocToken(), VaultID: "v"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect_url is required")
}

func TestOPConnectOpen_InvalidURL(t *testing.T) {
	_, err := opconnect.Open(opconnect.Options{ConnectURL: "http://bad\x7fhost", Token: bkocToken(), VaultID: bkocVault})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse connect_url")
	bkocNoToken(t, err)
}

func TestOPConnectGet_ListFailures(t *testing.T) {
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		want     string
		notFound bool
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, "HTTP 500", false},
		{"unauthorized", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }, "HTTP 403", false},
		{"bad json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) }, "decode response", false},
		{"truncated body", func(w http.ResponseWriter, _ *http.Request) { bkocTruncated(w) }, "read response", false},
		{"vault missing", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkocServe(t, tc.handler)
			b := bkocOpen(t, srv.URL, bkocVault)
			_, _, err := b.Get(context.Background(), "db/password")
			bkocNoToken(t, err)
			if tc.notFound {
				assert.True(t, errors.Is(err, backend.ErrNotFound), "got %v", err)
				return
			}
			assert.False(t, errors.Is(err, backend.ErrNotFound))
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), `op-connect Get "db/password"`)
		})
	}
}

func TestOPConnectGet_ItemFetchFailures(t *testing.T) {
	cases := []struct {
		name     string
		itemID   string
		handler  http.HandlerFunc
		want     string
		notFound bool
	}{
		{"item gone", "it1", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, "item it1", true},
		{"server error", "it1", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }, "HTTP 502", false},
		{"bad json", "it1", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }, "decode response", false},
		{"truncated body", "it1", func(w http.ResponseWriter, _ *http.Request) { bkocTruncated(w) }, "read response", false},
		{"invalid item id", "bad\x7fid", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }, "create request", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkocServe(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/vaults/"+bkocVault+"/items" {
					assert.Equal(t, "db/password", r.URL.Query().Get("title"))
					_, _ = w.Write([]byte(`[{"id":` + bkocJSONStr(tc.itemID) + `,"title":"db/password"}]`))
					return
				}
				tc.handler(w, r)
			})
			b := bkocOpen(t, srv.URL, bkocVault)
			_, _, err := b.Get(context.Background(), "db/password")
			bkocNoToken(t, err)
			assert.Equal(t, tc.notFound, errors.Is(err, backend.ErrNotFound), "got %v", err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func bkocJSONStr(s string) string {
	return `"` + strings.ReplaceAll(s, "\x7f", `\u007f`) + `"`
}

func TestOPConnectGet_TitleMismatchIsNotFound(t *testing.T) {
	srv := bkocServe(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"x","title":"db/password-old"}]`))
	})
	b := bkocOpen(t, srv.URL, bkocVault)
	_, _, err := b.Get(context.Background(), "db/password")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOPConnectTransportErrors(t *testing.T) {
	b := bkocOpen(t, bkocDeadURL(), bkocVault)
	ctx := context.Background()

	_, _, err := b.Get(ctx, "a")
	bkocNoToken(t, err)
	assert.Contains(t, err.Error(), "HTTP:")

	err = b.Set(ctx, "a", []byte("value"), backend.Meta{})
	bkocNoToken(t, err)
	assert.NotContains(t, err.Error(), "value")

	err = b.Delete(ctx, "a")
	bkocNoToken(t, err)
	assert.Contains(t, err.Error(), "list")

	_, err = b.List(ctx, "")
	bkocNoToken(t, err)
	assert.Contains(t, err.Error(), "op-connect List")
}

func TestOPConnectInvalidVaultIDRejectedBeforeSending(t *testing.T) {
	var hits int
	srv := bkocServe(t, func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	b := bkocOpen(t, srv.URL, "v\x7f")
	ctx := context.Background()

	err := b.Set(ctx, "a", []byte("v"), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")

	_, err = b.List(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create request")
	assert.Zero(t, hits)
}

func TestOPConnectSet_SendsConcealedPassword(t *testing.T) {
	secret := "pw-" + strings.Repeat("z", 12)
	srv := bkocServe(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusCreated)
	})
	b := bkocOpen(t, srv.URL, bkocVault)
	require.NoError(t, b.Set(context.Background(), "x", []byte(secret), backend.Meta{}))

	srv2 := bkocServe(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusConflict) })
	err := bkocOpen(t, srv2.URL, bkocVault).Set(context.Background(), "x", []byte(secret), backend.Meta{})
	bkocNoToken(t, err)
	assert.Contains(t, err.Error(), "HTTP 409")
	assert.NotContains(t, err.Error(), secret)
}

func TestOPConnectDelete_Failures(t *testing.T) {
	cases := []struct {
		name   string
		itemID string
		status int
		want   string
	}{
		{"server error", "it1", http.StatusInternalServerError, "HTTP 500"},
		{"invalid item id", "bad\x7fid", http.StatusOK, "create request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := bkocServe(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`[{"id":` + bkocJSONStr(tc.itemID) + `,"title":"k"}]`))
					return
				}
				w.WriteHeader(tc.status)
			})
			err := bkocOpen(t, srv.URL, bkocVault).Delete(context.Background(), "k")
			bkocNoToken(t, err)
			assert.NotErrorIs(t, err, backend.ErrNotFound)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("list error", func(t *testing.T) {
		srv := bkocServe(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
		err := bkocOpen(t, srv.URL, bkocVault).Delete(context.Background(), "k")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "list: HTTP 503")
	})

	t.Run("delete transport error", func(t *testing.T) {
		srv := bkocServe(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`[{"id":"it1","title":"k"}]`))
				return
			}
			bkocDropConn(w)
		})
		err := bkocOpen(t, srv.URL, bkocVault).Delete(context.Background(), "k")
		bkocNoToken(t, err)
		assert.Contains(t, err.Error(), `op-connect Delete "k"`)
	})
}

func TestOPConnectList_EmptyVaultOn404(t *testing.T) {
	srv := bkocServe(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	entries, err := bkocOpen(t, srv.URL, bkocVault).List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestOPConnectList_PrefixFiltersShortTitles(t *testing.T) {
	srv := bkocServe(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.Query().Get("title"))
		_, _ = w.Write([]byte(`[{"id":"1","title":"ab"},{"id":"2","title":"abc/x"},{"id":"3","title":"zzz/x"}]`))
	})
	entries, err := bkocOpen(t, srv.URL, bkocVault).List(context.Background(), "abc/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "abc/x", entries[0].Path)
	assert.Equal(t, backend.ID("2"), entries[0].Accessor)
	assert.True(t, entries[0].Exists)
}
