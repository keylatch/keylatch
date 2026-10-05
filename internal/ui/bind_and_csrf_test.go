package ui

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxServer(t *testing.T, mutate func(*ServerOptions)) *Server {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	opts := ServerOptions{
		Bind:       "127.0.0.1:0",
		SigningKey: key,
		Scope:      ScopeAdmin,
		Env:        func(string) string { return "" },
	}
	if mutate != nil {
		mutate(&opts)
	}
	srv, err := New(opts)
	require.NoError(t, err)
	return srv
}

func TestResolveBindAddr_Precedence(t *testing.T) {
	t.Parallel()
	envWith := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvListenKey {
				return v
			}
			return ""
		}
	}
	cases := []struct {
		name      string
		listen    string
		unsafeAll bool
		env       func(string) string
		wantBind  string
		wantAllow bool
	}{
		{"loopback default", "", false, nil, "127.0.0.1:7890", false},
		{"unsafe bind all", "", true, envWith(""), "0.0.0.0:7890", true},
		{"env listen", "", false, envWith("0.0.0.0:9000"), "0.0.0.0:9000", true},
		{"flag beats env", "10.1.2.3:80", false, envWith("0.0.0.0:9000"), "10.1.2.3:80", true},
		{"flag beats unsafe", "127.0.0.1:1", true, nil, "127.0.0.1:1", true},
	}
	for _, tc := range cases {
		bind, allow := ResolveBindAddr(7890, tc.listen, tc.unsafeAll, tc.env)
		assert.Equal(t, tc.wantBind, bind, tc.name)
		assert.Equal(t, tc.wantAllow, allow, tc.name)
	}
}

func TestIsLoopbackBind(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"127.0.0.1:80":     true,
		"127.9.9.9:1":      true,
		"[::1]:8080":       true,
		"localhost:1":      true,
		"localhost":        true,
		"[::1]":            true,
		"127.0.0.1":        true,
		"0.0.0.0:80":       false,
		"10.0.0.1":         false,
		"example.com:80":   false,
		"":                 false,
		"localhost.evil:1": false,
	}
	for addr, want := range cases {
		assert.Equal(t, want, isLoopbackBind(addr), addr)
	}
}

func TestSPAFallback(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/unknown", "/__internal"} {
		rec := httptest.NewRecorder()
		spaFallbackHandler(rec, httptest.NewRequest(http.MethodGet, p, nil))
		assert.Equal(t, http.StatusNotFound, rec.Code, p)
	}
	rec := httptest.NewRecorder()
	NewSPAFileServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "UI assets are not embedded")
}

func TestHandleCSRF_IssuesTokenCookie(t *testing.T) {
	t.Parallel()
	srv := mxServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/csrf", nil)
	req.RemoteAddr = "192.0.2.10:1111"
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.NotEmpty(t, body["csrf"])

	var cookieVal string
	for _, c := range rec.Result().Cookies() {
		if c.Value == body["csrf"] {
			cookieVal = c.Value
		}
	}
	assert.Equal(t, body["csrf"], cookieVal, "token must also be set as a cookie")

	req = httptest.NewRequest(http.MethodPost, "/api/csrf", nil)
	req.RemoteAddr = "192.0.2.10:1111"
	rec = httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestHandleBootstrap_RejectsNonGet(t *testing.T) {
	t.Parallel()
	srv := mxServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/__bootstrap?b=x&mac=y", nil)
	req.RemoteAddr = "192.0.2.11:1"
	rec := httptest.NewRecorder()
	srv.TestServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestNew_DefaultsAndLLMScopeCeiling(t *testing.T) {
	t.Parallel()
	srv := mxServer(t, func(o *ServerOptions) {
		o.Bind = ""
		o.Scope = ScopeTokenMinting
		o.Env = func(k string) string {
			if k == "CLAUDE_CODE" {
				return "1"
			}
			return ""
		}
	})
	assert.Equal(t, "127.0.0.1:7890", srv.opts.Bind)
	assert.Equal(t, ScopeStatusOnly, srv.opts.Scope)
	assert.True(t, strings.HasPrefix(srv.BootstrapURL(), "http://127.0.0.1:7890"))
}

func TestServe_ListenErrorWhenPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	srv := mxServer(t, func(o *ServerOptions) { o.Bind = ln.Addr().String() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Serve(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ui: listen on")
}

func TestExtractIP_WithoutPort(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "unix-socket"
	assert.Equal(t, "unix-socket", extractIP(r))
	r.RemoteAddr = "[2001:db8::1]:443"
	assert.Equal(t, "2001:db8::1", extractIP(r))
}

func TestCheckAndRecord_ThresholdAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	l := &bootstrapRateLimiter{maxFailures: 2, window: time.Minute, now: func() time.Time { return now }}

	assert.False(t, l.checkAndRecord("ip"))
	assert.False(t, l.checkAndRecord("ip"))
	assert.True(t, l.checkAndRecord("ip"), "at threshold the caller is blocked")
	assert.True(t, l.isBlocked("ip"))

	now = now.Add(2 * time.Minute)
	assert.False(t, l.checkAndRecord("ip"), "an expired window starts fresh")
	assert.False(t, l.isBlocked("ip"))
}

func TestScopeString_Unknown(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "unknown", UISessionScope(99).String())
}
