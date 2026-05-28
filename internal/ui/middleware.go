package ui

import (
	"net/http"
)

// cspValue is the Content-Security-Policy header value.
// Intentionally strict: no unsafe-eval, no unsafe-inline, no wildcards.
// 'self' covers the embedded SPA served from the same origin.
// Vite emits a standalone CSS file (not inline styles), so unsafe-inline
// is not required for style-src.
const cspValue = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// SecurityHeaders sets required security response headers on every response:
//   - Cache-Control: no-store (prevents caching of potentially sensitive UI)
//   - X-Frame-Options: DENY (clickjacking protection)
//   - X-Content-Type-Options: nosniff (MIME sniffing protection)
//   - Referrer-Policy: no-referrer (no URL leakage in Referer headers)
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// StrictCSP adds the Content-Security-Policy header. It is applied on top of
// SecurityHeaders for the SPA and API routes.
func StrictCSP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspValue)
		next.ServeHTTP(w, r)
	})
}

// chain applies a sequence of middleware in order (outermost first).
func chain(h http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}
