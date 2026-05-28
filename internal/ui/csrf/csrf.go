// Package csrf implements a double-submit-cookie CSRF protection mechanism.
//
// Pattern: the server issues a random token in a readable cookie (kl_csrf)
// AND expects the same token in the X-CSRF-Token request header. Because
// an attacker's site cannot read the cookie value (SameSite=Strict + different
// origin), it cannot forge the header.
//
// Security invariants:
//   - CSRF token is never stored server-side (stateless double-submit).
//   - All write endpoints (POST/PUT/DELETE/PATCH) require a valid CSRF token.
//   - GET/HEAD/OPTIONS are exempt (safe methods).
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

const (
	// CookieName is the readable CSRF cookie name.
	CookieName = "kl_csrf"

	// HeaderName is the request header the client must echo.
	HeaderName = "X-CSRF-Token"

	// tokenLen is the length of the random token in bytes.
	tokenLen = 32
)

// ErrMissing is returned when no CSRF token is present in the request.
var ErrMissing = errors.New("csrf: token missing")

// ErrMismatch is returned when the header value does not match the cookie.
var ErrMismatch = errors.New("csrf: token mismatch")

// IssueToken generates a new random CSRF token string.
func IssueToken() (string, error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("csrf: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SetCookie writes the CSRF token as a readable (non-HttpOnly) cookie so that
// JavaScript can read it and echo it in X-CSRF-Token headers.
func SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure flag intentionally absent; server binds to 127.0.0.1 only (no TLS on loopback)
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // must be readable by JS
		SameSite: http.SameSiteStrictMode,
	})
}

// Validate checks that the X-CSRF-Token header matches the kl_csrf cookie.
// Returns nil on success.
func Validate(r *http.Request) error {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return ErrMissing
	}
	header := r.Header.Get(HeaderName)
	if header == "" {
		return ErrMissing
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(header)) {
		return ErrMismatch
	}
	return nil
}

// Middleware wraps an http.Handler and enforces CSRF validation on write methods.
// GET, HEAD, OPTIONS are exempted (safe methods per RFC 7231).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Safe methods: no CSRF check required.
		default:
			if err := Validate(r); err != nil {
				http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
