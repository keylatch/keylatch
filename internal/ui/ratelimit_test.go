package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBootstrapRateLimit_SixthRequestReturns429 verifies that after 5 failed
// requests from the same IP, the sixth returns 429 Too Many Requests.
// This implements T-13-01 acceptance criterion.
func TestBootstrapRateLimit_SixthRequestReturns429(t *testing.T) {
	t.Parallel()

	limiter := &bootstrapRateLimiter{
		maxFailures: 5,
		window:      15 * time.Minute,
		now:         time.Now,
	}

	// Handler that always returns 401 (simulates wrong bootstrap token).
	handler := withBootstrapRateLimit(limiter, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	// Send 5 requests — all should pass through to the handler (return 401).
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/__bootstrap?b=badtoken", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: expected 401, got %d", i+1, rr.Code)
		}
	}

	// Sixth request — must return 429.
	req := httptest.NewRequest(http.MethodGet, "/__bootstrap?b=badtoken", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("sixth request: expected 429, got %d", rr.Code)
	}
}

// TestBootstrapRateLimit_ResetOnSuccess verifies that a successful auth resets
// the counter so subsequent requests pass through again.
func TestBootstrapRateLimit_ResetOnSuccess(t *testing.T) {
	t.Parallel()

	limiter := &bootstrapRateLimiter{
		maxFailures: 3,
		window:      15 * time.Minute,
		now:         time.Now,
	}

	// First: fail 3 times.
	failHandler := withBootstrapRateLimit(limiter, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		failHandler(httptest.NewRecorder(), req)
	}

	// Should now be blocked.
	req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	failHandler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after 3 failures, got %d", rec.Code)
	}

	// Simulate a successful auth (counter reset via recordSuccess directly).
	limiter.recordSuccess("10.0.0.1")

	// Should now be unblocked.
	req = httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	failHandler(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("expected request to pass after success reset, got 429")
	}
}

// TestBootstrapRateLimit_WindowExpiry verifies that after the window expires,
// the counter resets and new failures are allowed.
func TestBootstrapRateLimit_WindowExpiry(t *testing.T) {
	t.Parallel()

	// Use a mock clock that starts in the past.
	now := time.Now()
	mockNow := func() time.Time { return now }

	limiter := &bootstrapRateLimiter{
		maxFailures: 2,
		window:      15 * time.Minute,
		now:         mockNow,
	}

	handler := withBootstrapRateLimit(limiter, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	// Fail twice to hit the limit.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
		req.RemoteAddr = "192.168.1.1:9999"
		handler(httptest.NewRecorder(), req)
	}

	// Confirm blocked.
	req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
	req.RemoteAddr = "192.168.1.1:9999"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	// Advance clock past window.
	now = now.Add(16 * time.Minute)

	// Should now be unblocked (window expired).
	req = httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
	req.RemoteAddr = "192.168.1.1:9999"
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("expected request to pass after window expiry, got 429")
	}
}

// TestBootstrapRateLimit_DifferentIPs verifies that counters are per-IP.
func TestBootstrapRateLimit_DifferentIPs(t *testing.T) {
	t.Parallel()

	limiter := &bootstrapRateLimiter{
		maxFailures: 2,
		window:      15 * time.Minute,
		now:         time.Now,
	}

	handler := withBootstrapRateLimit(limiter, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	// Exhaust IP1.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
		req.RemoteAddr = "1.1.1.1:1234"
		handler(httptest.NewRecorder(), req)
	}

	// IP2 should still be allowed.
	req := httptest.NewRequest(http.MethodGet, "/__bootstrap", nil)
	req.RemoteAddr = "2.2.2.2:1234"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("IP2 should not be rate-limited by IP1's failures")
	}
}
