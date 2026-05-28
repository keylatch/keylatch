package session_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signingKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestNew_RequiresExactly32ByteKey(t *testing.T) {
	t.Parallel()
	_, err := session.New(make([]byte, 16))
	require.Error(t, err)

	_, err = session.New(make([]byte, 32))
	require.NoError(t, err)
}

func TestURL_ContainsToken(t *testing.T) {
	t.Parallel()
	s, err := session.New(signingKey(t))
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	assert.Contains(t, u, "/__bootstrap?b=")
	assert.Contains(t, u, "&mac=")
	// Token must be in URL
	assert.True(t, strings.Contains(u, "b="), "URL must contain b= parameter")
}

func TestConsumeBootstrap_Success(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	// Parse token and mac from URL
	parts := strings.Split(u, "?")
	require.Len(t, parts, 2)
	params := strings.Split(parts[1], "&")
	var tok, mac string
	for _, p := range params {
		if strings.HasPrefix(p, "b=") {
			tok = strings.TrimPrefix(p, "b=")
		}
		if strings.HasPrefix(p, "mac=") {
			mac = strings.TrimPrefix(p, "mac=")
		}
	}

	cookieVal, err := s.ConsumeBootstrap(tok, mac)
	require.NoError(t, err)
	assert.NotEmpty(t, cookieVal)
}

func TestConsumeBootstrap_OnlyOnce(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	tok, mac := parseBootstrapURL(t, u)

	_, err = s.ConsumeBootstrap(tok, mac)
	require.NoError(t, err)

	// Second call must fail
	_, err = s.ConsumeBootstrap(tok, mac)
	require.ErrorIs(t, err, session.ErrTokenConsumed)
}

func TestConsumeBootstrap_InvalidMAC(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	tok, _ := parseBootstrapURL(t, u)

	_, err = s.ConsumeBootstrap(tok, "deadbeefdeadbeefdeadbeefdeadbeef")
	require.ErrorIs(t, err, session.ErrInvalidHMAC)
}

func TestConsumeBootstrap_WrongToken(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	_, mac := parseBootstrapURL(t, u)

	_, err = s.ConsumeBootstrap("wrongtoken", mac)
	require.Error(t, err)
}

func TestValidateRequest_Valid(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	u := s.URL("http://127.0.0.1:7890")
	tok, mac := parseBootstrapURL(t, u)

	cookieVal, err := s.ConsumeBootstrap(tok, mac)
	require.NoError(t, err)

	// Build a fake response to set cookie, then read it on a request
	rec := httptest.NewRecorder()
	s.SetCookie(rec, cookieVal)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	require.NoError(t, s.ValidateRequest(req))
}

func TestValidateRequest_MissingCookie(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	err = s.ValidateRequest(req)
	require.ErrorIs(t, err, session.ErrUnknownSession)
}

func TestValidateRequest_WrongCookieValue(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.CookieName(), Value: "wrongvalue"})

	err = s.ValidateRequest(req)
	require.ErrorIs(t, err, session.ErrUnknownSession)
}

func TestSetCookie_IsHttpOnly(t *testing.T) {
	t.Parallel()
	k := signingKey(t)
	s, err := session.New(k)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	s.SetCookie(rec, "testval")

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.True(t, cookies[0].HttpOnly, "session cookie must be HttpOnly")
}

// parseBootstrapURL extracts token and mac from a bootstrap URL.
func parseBootstrapURL(t *testing.T, u string) (tok, mac string) {
	t.Helper()
	parts := strings.Split(u, "?")
	require.Len(t, parts, 2)
	for _, p := range strings.Split(parts[1], "&") {
		if strings.HasPrefix(p, "b=") {
			tok = strings.TrimPrefix(p, "b=")
		}
		if strings.HasPrefix(p, "mac=") {
			mac = strings.TrimPrefix(p, "mac=")
		}
	}
	return
}
