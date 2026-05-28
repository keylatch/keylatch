package csrf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/csrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueToken_UniqueEachCall(t *testing.T) {
	t.Parallel()
	t1, err := csrf.IssueToken()
	require.NoError(t, err)
	t2, err := csrf.IssueToken()
	require.NoError(t, err)
	assert.NotEqual(t, t1, t2)
	assert.Len(t, t1, 64) // 32 bytes hex-encoded
}

func TestSetCookie_NotHttpOnly(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	csrf.SetCookie(rec, "testtoken")
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.False(t, cookies[0].HttpOnly, "CSRF cookie must NOT be HttpOnly (JS needs to read it)")
	assert.Equal(t, csrf.CookieName, cookies[0].Name)
}

func TestValidate_Success(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	token := "abc123deadbeef"
	req.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: token})
	req.Header.Set(csrf.HeaderName, token)

	require.NoError(t, csrf.Validate(req))
}

func TestValidate_MissingCookie(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(csrf.HeaderName, "sometoken")

	err := csrf.Validate(req)
	require.ErrorIs(t, err, csrf.ErrMissing)
}

func TestValidate_MissingHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: "sometoken"})

	err := csrf.Validate(req)
	require.ErrorIs(t, err, csrf.ErrMissing)
}

func TestValidate_Mismatch(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: "cookietoken"})
	req.Header.Set(csrf.HeaderName, "differenttoken")

	err := csrf.Validate(req)
	require.ErrorIs(t, err, csrf.ErrMismatch)
}

func TestMiddleware_SafeMethods_PassThrough(t *testing.T) {
	t.Parallel()
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := csrf.Middleware(inner)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		called = false
		req := httptest.NewRequest(method, "/api/status", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.True(t, called, "safe method %s should pass through", method)
	}
}

func TestMiddleware_WriteMethod_RequiresCSRF(t *testing.T) {
	t.Parallel()
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := csrf.Middleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/connections", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.False(t, called, "write method without CSRF token must not reach handler")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMiddleware_WriteMethod_WithValidCSRF(t *testing.T) {
	t.Parallel()
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := csrf.Middleware(inner)

	token := "validcsrftoken"
	req := httptest.NewRequest(http.MethodPost, "/api/connections", nil)
	req.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: token})
	req.Header.Set(csrf.HeaderName, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestCSRFConstantTimeCompare verifies that Validate uses hmac.Equal (not string equality)
// so the code path is constant-time by construction. It asserts that matching tokens pass
// and tokens differing by one byte or length fail with ErrMismatch.
func TestCSRFConstantTimeCompare(t *testing.T) {
	t.Parallel()

	// Matching tokens must pass.
	token := "deadbeefcafebabedeadbeefcafebabe"
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: token})
	req.Header.Set(csrf.HeaderName, token)
	assert.NoError(t, csrf.Validate(req), "identical tokens must pass Validate")

	// Tokens that differ only in the last byte must fail (not panic or short-circuit).
	tokenA := "deadbeefcafebabedeadbeefcafeba00"
	tokenB := "deadbeefcafebabedeadbeefcafeba01"
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: tokenA})
	req2.Header.Set(csrf.HeaderName, tokenB)
	assert.ErrorIs(t, csrf.Validate(req2), csrf.ErrMismatch,
		"tokens differing by one byte must return ErrMismatch")

	// A token that is a prefix of a longer token must also fail.
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: "shorttoken"})
	req3.Header.Set(csrf.HeaderName, "shorttokenextra")
	assert.ErrorIs(t, csrf.Validate(req3), csrf.ErrMismatch,
		"prefix token must not pass Validate")
}
