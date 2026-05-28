package mcp

import (
	"testing"
	"time"
)

// TestBearerSessionIdleTimeout verifies that a bearer session is marked
// expired when no request has been made within bearerIdleTimeout (A4-009 / m4).
func TestBearerSessionIdleTimeout(t *testing.T) {
	// Create a session with a 1-hour wall-clock TTL.
	s := newBearerSession("test-token", time.Hour)

	// Session is fresh — CheckAndTouch should succeed.
	if err := s.CheckAndTouch("test-token"); err != nil {
		t.Fatalf("expected success for fresh token, got %v", err)
	}

	// Simulate 31 minutes of idle by backdating lastUsedAt.
	s.mu.Lock()
	s.lastUsedAt = time.Now().Add(-31 * time.Minute)
	s.mu.Unlock()

	// Now the token is idle — CheckAndTouch must return ErrSessionTokenExpired.
	err := s.CheckAndTouch("test-token")
	if err != ErrSessionTokenExpired {
		t.Errorf("expected ErrSessionTokenExpired for idle token, got %v", err)
	}
}

// TestBearerSessionTokenMismatch verifies that a wrong token returns ErrSessionTokenMismatch.
func TestBearerSessionTokenMismatch(t *testing.T) {
	s := newBearerSession("correct-token", time.Hour)

	err := s.CheckAndTouch("wrong-token")
	if err != ErrSessionTokenMismatch {
		t.Errorf("expected ErrSessionTokenMismatch, got %v", err)
	}
}

// TestBearerSessionWallClockExpiry verifies that a session expired by wall clock
// is rejected even if lastUsedAt is recent.
func TestBearerSessionWallClockExpiry(t *testing.T) {
	// Create a session with a very short TTL.
	s := newBearerSession("test-token", time.Millisecond)

	// Wait just past the TTL.
	time.Sleep(5 * time.Millisecond)

	err := s.CheckAndTouch("test-token")
	if err != ErrTTLExceedsCap {
		t.Errorf("expected ErrTTLExceedsCap for wall-clock-expired token, got %v", err)
	}
}

// TestBearerSessionIsExpired verifies IsExpired reports correctly.
func TestBearerSessionIsExpired(t *testing.T) {
	s := newBearerSession("test-token", time.Hour)

	if s.IsExpired() {
		t.Error("fresh session should not be expired")
	}

	// Backdate lastUsedAt past idle timeout.
	s.mu.Lock()
	s.lastUsedAt = time.Now().Add(-31 * time.Minute)
	s.mu.Unlock()

	if !s.IsExpired() {
		t.Error("idle session should be expired")
	}
}

// TestBearerSessionTouchResetsIdle verifies that a successful CheckAndTouch
// resets the idle timer so a subsequent call within 30 minutes succeeds.
func TestBearerSessionTouchResetsIdle(t *testing.T) {
	s := newBearerSession("test-token", time.Hour)

	// Simulate 20 minutes of idle — still within the 30 min window.
	s.mu.Lock()
	s.lastUsedAt = time.Now().Add(-20 * time.Minute)
	s.mu.Unlock()

	// Touch resets lastUsedAt to now.
	if err := s.CheckAndTouch("test-token"); err != nil {
		t.Fatalf("expected success for 20-min idle token, got %v", err)
	}

	// Now simulate another 20 minutes — still within window because Touch reset it.
	s.mu.Lock()
	s.lastUsedAt = time.Now().Add(-20 * time.Minute)
	s.mu.Unlock()

	if err := s.CheckAndTouch("test-token"); err != nil {
		t.Fatalf("expected success after touch + 20min idle, got %v", err)
	}
}
