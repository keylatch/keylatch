package session

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDesktopBootstrapIsSingleUseAndSessionBound(t *testing.T) {
	s, err := New(make([]byte, 32))
	require.NoError(t, err)
	other, err := New(make([]byte, 32))
	require.NoError(t, err)
	token, expires, err := s.MintBootstrapToken()
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(time.Minute), expires, time.Second)
	_, err = other.ConsumeDesktopBootstrap(token)
	require.Error(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	require.Error(t, s.ValidateRequest(req))

	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Go(func() {
			cookie, err := s.ConsumeDesktopBootstrap(token)
			if err == nil {
				results <- cookie
			}
		})
	}
	wg.Wait()
	close(results)
	require.Len(t, results, 1)
	req = httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: <-results})
	require.NoError(t, s.ValidateRequest(req))
}

func TestDesktopBootstrapExpiresAndLimitsOutstandingTokens(t *testing.T) {
	s, err := New(make([]byte, 32))
	require.NoError(t, err)
	token, _, err := s.MintBootstrapToken()
	require.NoError(t, err)
	s.desktopTokens[sha256.Sum256([]byte(token))] = time.Now().Add(-time.Second)
	_, err = s.ConsumeDesktopBootstrap(token)
	require.ErrorIs(t, err, ErrTokenExpired)
	for range 16 {
		_, _, err := s.MintBootstrapToken()
		require.NoError(t, err)
	}
	_, _, err = s.MintBootstrapToken()
	require.Error(t, err)
	s.expiresAt = time.Now().Add(-time.Second)
	_, _, err = s.MintBootstrapToken()
	require.NoError(t, err)
}

func TestDesktopRenewalRevokesOldCredentialsWithoutRevivingHTTPBootstrap(t *testing.T) {
	s, err := New(make([]byte, 32))
	require.NoError(t, err)
	oldToken, oldMAC := s.token, s.computeMAC(s.token)
	oldDesktop, _, err := s.MintBootstrapToken()
	require.NoError(t, err)
	oldCookie := s.id
	s.expiresAt = time.Now().Add(-time.Second)
	req := httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: oldCookie})
	require.ErrorIs(t, s.ValidateRequest(req), ErrTokenExpired)
	_, err = s.ConsumeBootstrap(oldToken, oldMAC)
	require.ErrorIs(t, err, ErrTokenExpired)

	token, _, err := s.MintBootstrapToken()
	require.NoError(t, err)
	require.NotEqual(t, oldCookie, s.id)
	require.ErrorIs(t, s.ValidateRequest(req), ErrUnknownSession)
	_, err = s.ConsumeDesktopBootstrap(oldDesktop)
	require.ErrorIs(t, err, ErrUnknownSession)
	_, err = s.ConsumeBootstrap(oldToken, oldMAC)
	require.ErrorIs(t, err, ErrTokenConsumed)
	cookie, err := s.ConsumeDesktopBootstrap(token)
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodGet, "/api/approvals", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	require.NoError(t, s.ValidateRequest(req))
	second, _, err := s.MintBootstrapToken()
	require.NoError(t, err)
	secondCookie, err := s.ConsumeDesktopBootstrap(second)
	require.NoError(t, err)
	require.Equal(t, cookie, secondCookie)
}

func TestDesktopBootstrapPrunesStaleTokensAndCannotOutliveSession(t *testing.T) {
	s, err := New(make([]byte, 32))
	require.NoError(t, err)
	for range 16 {
		_, _, err := s.MintBootstrapToken()
		require.NoError(t, err)
	}
	for digest := range s.desktopTokens {
		s.desktopTokens[digest] = time.Now().Add(-time.Second)
	}
	s.expiresAt = time.Now().Add(10 * time.Second)
	token, expires, err := s.MintBootstrapToken()
	require.NoError(t, err)
	require.Equal(t, s.expiresAt, expires)
	s.expiresAt = time.Now().Add(-time.Second)
	_, err = s.ConsumeDesktopBootstrap(token)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestConcurrentDesktopRenewalsKeepOneSession(t *testing.T) {
	s, err := New(make([]byte, 32))
	require.NoError(t, err)
	s.expiresAt = time.Now().Add(-time.Second)
	var wg sync.WaitGroup
	cookies := make(chan string, 8)
	for range 8 {
		wg.Go(func() {
			token, _, mintErr := s.MintBootstrapToken()
			if mintErr != nil {
				t.Error(mintErr)
				return
			}
			cookie, consumeErr := s.ConsumeDesktopBootstrap(token)
			if consumeErr != nil {
				t.Error(consumeErr)
				return
			}
			cookies <- cookie
		})
	}
	wg.Wait()
	close(cookies)
	require.Len(t, cookies, 8)
	for cookie := range cookies {
		require.Equal(t, s.id, cookie)
	}
}
