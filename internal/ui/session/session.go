// Package session manages one-time bootstrap tokens and UI session cookies
// for the keylatch UI server.
//
// Security invariants:
// - bootstrap token appears in URL only once (/__bootstrap?b=...),
// then is exchanged for an HttpOnly cookie; the token never appears in any
// subsequent URL.
// - bootstrap HMAC uses crypto/hmac; replayed tokens are rejected.
// - Session state is not persisted to disk; it lives only in memory.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// cookieName is the HttpOnly session cookie name.
const cookieName = "kl_session"

// tokenLen is the length of a random bootstrap token in bytes.
const tokenLen = 32

// defaultTTL is how long a session remains valid after creation.
const defaultTTL = 8 * time.Hour

// ErrTokenConsumed is returned when ConsumeBootstrap is called more than once.
var ErrTokenConsumed = errors.New("session: bootstrap token already consumed")

// ErrTokenExpired is returned when the session has expired.
var ErrTokenExpired = errors.New("session: session expired")

// ErrInvalidHMAC is returned when the HMAC on the bootstrap token is invalid.
var ErrInvalidHMAC = errors.New("session: invalid HMAC on bootstrap token")

// ErrUnknownSession is returned when ValidateRequest cannot find a matching session.
var ErrUnknownSession = errors.New("session: unknown or expired session cookie")

// Session holds the one-time bootstrap token and tracks its consumed state.
type Session struct {
	mu        sync.Mutex
	id        string
	hmacKey   []byte
	token     string // hex-encoded random bytes
	consumed  bool
	expiresAt time.Time
}

// New creates a new Session. signingKey must be 32 bytes; it is used both for
// generating the bootstrap HMAC and for validating session cookies.
func New(signingKey []byte) (*Session, error) {
	if len(signingKey) != 32 {
		return nil, fmt.Errorf("session: signing key must be 32 bytes, got %d", len(signingKey))
	}
	rawToken := make([]byte, tokenLen)
	if _, err := rand.Read(rawToken); err != nil {
		return nil, fmt.Errorf("session: generate token: %w", err)
	}
	rawID := make([]byte, 16)
	if _, err := rand.Read(rawID); err != nil {
		return nil, fmt.Errorf("session: generate id: %w", err)
	}
	s := &Session{
		id:        hex.EncodeToString(rawID),
		hmacKey:   signingKey,
		token:     hex.EncodeToString(rawToken),
		consumed:  false,
		expiresAt: time.Now().Add(defaultTTL),
	}
	return s, nil
}

// URL returns the bootstrap URL for the given base address. The token appears
// exactly once — in this URL — and is consumed on first exchange.
// after exchange the token must never appear in any URL again.
func (s *Session) URL(base string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac := s.computeMAC(s.token)
	return fmt.Sprintf("%s/__bootstrap?b=%s&mac=%s", base, s.token, mac)
}

// ConsumeBootstrap validates and consumes the bootstrap token. It returns the
// session cookie value to set on the response. Errors if already consumed,
// expired, or the HMAC is invalid.
func (s *Session) ConsumeBootstrap(token, mac string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.consumed {
		return "", ErrTokenConsumed
	}
	if time.Now().After(s.expiresAt) {
		return "", ErrTokenExpired
	}
	if !hmac.Equal([]byte(mac), []byte(s.computeMAC(token))) {
		return "", ErrInvalidHMAC
	}
	if token != s.token {
		return "", ErrInvalidHMAC
	}
	s.consumed = true
	return s.id, nil
}

// ValidateRequest checks the kl_session cookie on the incoming request against
// this session. Returns nil on success.
func (s *Session) ValidateRequest(r *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().After(s.expiresAt) {
		return ErrTokenExpired
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ErrUnknownSession
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(s.id)) {
		return ErrUnknownSession
	}
	return nil
}

// SetCookie writes the HttpOnly session cookie to the response writer.
func (s *Session) SetCookie(w http.ResponseWriter, cookieVal string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure flag intentionally absent; server binds to 127.0.0.1 only (no TLS on loopback)
		Name:     cookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// No Secure flag: this server binds to 127.0.0.1 only and uses HTTP.
	})
}

// CookieName returns the session cookie name (exported for middleware use).
func CookieName() string { return cookieName }

// computeMAC returns the HMAC-SHA256 of data under the session key, hex-encoded.
// Caller must hold s.mu.
func (s *Session) computeMAC(data string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
