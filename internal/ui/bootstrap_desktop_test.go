package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/sidecar/events"
	"github.com/keylatch/keylatch/internal/sidecar/ipc"
	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/require"
)

func TestDesktopBootstrapIPCResultAuthenticatesHTTP(t *testing.T) {
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)
	registry := ipc.NewMethodRegistry()
	mux := events.NewMux()
	defer mux.Stop()
	ipc.RegisterHandlers(registry, mux, srv, nil)
	for range 2 {
		response := registry.Dispatch(t.Context(), ipc.Request{Method: ipc.MethodMintBootstrapToken}, nil)
		require.Empty(t, response.Error)
		token := response.Result.(map[string]any)["token"].(string)
		bootstrap := httptest.NewRecorder()
		srv.TestServeHTTP(bootstrap, httptest.NewRequest(http.MethodPost, "/__bootstrap", strings.NewReader(`{"token":"`+token+`"}`)))
		require.Equal(t, http.StatusNoContent, bootstrap.Code)
		require.Empty(t, bootstrap.Header().Get("Location"))
		require.Equal(t, "no-store", bootstrap.Header().Get("Cache-Control"))
		require.NotContains(t, bootstrap.Body.String(), token)
		cookie := findCookie(bootstrap, "kl_session")
		require.NotNil(t, cookie)
		require.True(t, cookie.HttpOnly)
		require.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
		require.NotNil(t, findCookie(bootstrap, "kl_csrf"))
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.TestServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		replay := httptest.NewRecorder()
		srv.TestServeHTTP(replay, httptest.NewRequest(http.MethodPost, "/__bootstrap", strings.NewReader(`{"token":"`+token+`"}`)))
		require.Equal(t, http.StatusUnauthorized, replay.Code)
	}
}

func TestDesktopBootstrapLoadingPageContainsNoCredential(t *testing.T) {
	srv, err := ui.New(defaultOpts(t))
	require.NoError(t, err)
	token, _, err := srv.MintBootstrapToken()
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__bootstrap", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Connecting to Keylatch")
	require.NotContains(t, rec.Body.String(), token)
	require.Empty(t, rec.Result().Cookies())
}
