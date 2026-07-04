// Package ui — rate limiting middleware for bootstrap endpoints.
package ui

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimitEntry holds the failure counter and reset time for a single IP.
type rateLimitEntry struct {
	failures int
	resetAt  time.Time
}

// bootstrapRateLimiter is an in-memory per-IP rate limiter for the bootstrap
// and CSRF endpoints. It tracks failed attempts (wrong token) and returns 429
// after maxFailures within the window duration.
//
// The limiter is intentionally simple: one sync.Map, no external dependency.
type bootstrapRateLimiter struct {
	mu          sync.Mutex
	entries     sync.Map
	maxFailures int
	window      time.Duration
	now         func() time.Time // injectable for tests
}

// newBootstrapRateLimiter returns a rate limiter configured per spec:
// 5 failed attempts per IP before 429, counter resets after 15 minutes.
func newBootstrapRateLimiter() *bootstrapRateLimiter {
	return &bootstrapRateLimiter{
		maxFailures: 5,
		window:      15 * time.Minute,
		now:         time.Now,
	}
}

// extractIP returns the remote IP address from r, stripping any port.
func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// SplitHostPort failed — return RemoteAddr as-is (no port in addr).
		return r.RemoteAddr
	}
	return host
}

// checkAndRecord atomically checks whether ip is currently blocked and, if not,
// records a new failure. It holds the mutex for the entire read-check-write
// sequence to eliminate the TOCTOU window that existed when isBlocked and
// recordFailure were called separately.
//
// Returns true if the IP was already at or above the failure threshold (i.e.
// the caller should return 429). Returns false if the failure was recorded and
// the IP has not yet reached the threshold.
func (l *bootstrapRateLimiter) checkAndRecord(ip string) (blocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	v, ok := l.entries.Load(ip)
	if !ok {
		// First failure for this IP.
		l.entries.Store(ip, rateLimitEntry{failures: 1, resetAt: now.Add(l.window)})
		return false
	}

	entry := v.(rateLimitEntry)
	if now.After(entry.resetAt) {
		// Window expired — start fresh.
		l.entries.Store(ip, rateLimitEntry{failures: 1, resetAt: now.Add(l.window)})
		return false
	}

	// Already at or past the threshold — blocked, do not increment further.
	if entry.failures >= l.maxFailures {
		return true
	}

	// Increment and check if this failure tips over the threshold.
	entry.failures++
	l.entries.Store(ip, entry)
	return false
}

// isBlocked reports whether ip is currently at or above the failure threshold.
// It acquires the mutex so the read is consistent with checkAndRecord writes.
func (l *bootstrapRateLimiter) isBlocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, ok := l.entries.Load(ip)
	if !ok {
		return false
	}
	entry := v.(rateLimitEntry)
	if l.now().After(entry.resetAt) {
		l.entries.Delete(ip)
		return false
	}
	return entry.failures >= l.maxFailures
}

// recordSuccess resets the failure counter for ip (successful authentication).
func (l *bootstrapRateLimiter) recordSuccess(ip string) {
	l.entries.Delete(ip)
}

// defaultRateLimiter is the package-level limiter used by handleBootstrap and handleCSRF.
var defaultRateLimiter = newBootstrapRateLimiter()

// withBootstrapRateLimit wraps h with per-IP rate limiting.
//
// If the IP has exceeded the failure threshold, the wrapper returns 429 and
// does not invoke h. When h returns HTTP 401 (wrong token), the wrapper calls
// checkAndRecord atomically — a single mutex-held read-check-write that
// eliminates the TOCTOU window between the old isBlocked + recordFailure pair.
// On HTTP 200/303, it records a success (reset counter).
func withBootstrapRateLimit(limiter *bootstrapRateLimiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		if limiter.isBlocked(ip) {
			http.Error(w, "too many failed attempts — try again later", http.StatusTooManyRequests)
			return
		}

		// Use a response recorder to capture the status code.
		rw := &statusCapturingWriter{ResponseWriter: w}
		h(rw, r)

		switch rw.status {
		case http.StatusUnauthorized:
			limiter.checkAndRecord(ip)
		case 0, http.StatusOK, http.StatusSeeOther:
			// 0 means no explicit WriteHeader was called — treat as success.
			limiter.recordSuccess(ip)
		}
	}
}

// statusCapturingWriter wraps http.ResponseWriter to capture the written status code.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
