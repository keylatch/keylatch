package budget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestCounter(t *testing.T, policy BudgetPolicy) *InMemoryBudgetCounter {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return NewInMemoryBudgetCounter(ctx, policy)
}

// TestCheckAndRecord_EnforcesLimit covers the atomic check+record path.
func TestCheckAndRecord_EnforcesLimit(t *testing.T) {
	t.Parallel()
	c := newTestCounter(t, BudgetPolicy{SpendPerHour: 2})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := c.CheckAndRecord(ctx, "actor", "cap", 1); err != nil {
			t.Fatalf("within budget call %d: %v", i+1, err)
		}
	}
	if err := c.CheckAndRecord(ctx, "actor", "cap", 1); err != ErrBudgetExceeded {
		t.Errorf("over budget: got %v, want ErrBudgetExceeded", err)
	}
	// A different actor has an independent window.
	if err := c.CheckAndRecord(ctx, "other", "cap", 1); err != nil {
		t.Errorf("independent actor: %v", err)
	}
	// Denied attempts must not consume budget: 'other' still has 1 left.
	if err := c.CheckAndRecord(ctx, "other", "cap", 1); err != nil {
		t.Errorf("independent actor second call: %v", err)
	}
}

// TestCheck_ReadOnly verifies Check does not reserve budget.
func TestCheck_ReadOnly(t *testing.T) {
	t.Parallel()
	c := newTestCounter(t, BudgetPolicy{SpendPerHour: 1})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := c.Check(ctx, "a", "cap", 1); err != nil {
			t.Fatalf("Check %d must pass on fresh window: %v", i, err)
		}
	}
	if err := c.Record(ctx, "a", "cap", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := c.Check(ctx, "a", "cap", 1); err != ErrBudgetExceeded {
		t.Errorf("Check after limit reached: got %v, want ErrBudgetExceeded", err)
	}
}

// TestRelevantKeys_AllPolicyDimensions ensures every configured limit creates
// a window and enforces independently.
func TestRelevantKeys_AllPolicyDimensions(t *testing.T) {
	t.Parallel()
	c := newTestCounter(t, BudgetPolicy{
		SpendPerHour:         10,
		SpendPerDay:          20,
		EmailSendsPerHour:    1,
		SlackMessagesPerHour: 2,
		DNSMutationsPerDay:   3,
		AWSActionCount:       4,
		StripeRefundAmount:   5,
		DownloadBytesLimit:   6,
	})
	keys := c.relevantKeys("a", "cap")
	if len(keys) != 8 {
		t.Fatalf("relevantKeys: got %d keys, want 8", len(keys))
	}
	// EmailSendsPerHour=1 is the tightest: second unit must exceed it.
	ctx := context.Background()
	if err := c.CheckAndRecord(ctx, "a", "cap", 1); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := c.CheckAndRecord(ctx, "a", "cap", 1); err != ErrBudgetExceeded {
		t.Errorf("second unit must exceed the 1/h dimension, got %v", err)
	}
}

// TestEvictExpired removes stale windows.
func TestEvictExpired(t *testing.T) {
	t.Parallel()
	c := newTestCounter(t, BudgetPolicy{SpendPerHour: 1})
	ctx := context.Background()
	if err := c.Record(ctx, "a", "cap", 1); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	if len(c.windows) == 0 {
		c.mu.Unlock()
		t.Fatal("expected a live window")
	}
	// Force-expire all windows, then evict.
	for _, b := range c.windows {
		b.windowEnd = time.Now().Add(-time.Minute)
	}
	c.mu.Unlock()
	c.evictExpired()
	c.mu.Lock()
	n := len(c.windows)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("evictExpired left %d windows, want 0", n)
	}
	// Expired window means the budget is fresh again.
	if err := c.CheckAndRecord(ctx, "a", "cap", 1); err != nil {
		t.Errorf("after eviction: %v", err)
	}
}

// TestBudgetMiddleware_Handler covers the HTTP wrapper: pass within budget,
// 429 with a value-free receipt when exceeded.
func TestBudgetMiddleware_Handler(t *testing.T) {
	t.Parallel()
	c := newTestCounter(t, BudgetPolicy{SpendPerHour: 1})
	m := NewBudgetMiddleware(c, "cap", 1)

	nextCalls := 0
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("X-Keylatch-Actor", "raw-actor-id")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || nextCalls != 1 {
		t.Fatalf("first call: code=%d nextCalls=%d", rr.Code, nextCalls)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second call: code=%d, want 429", rr.Code)
	}
	if nextCalls != 1 {
		t.Errorf("next handler ran on denied request")
	}
	body := rr.Body.String()
	if strings.Contains(body, "raw-actor-id") {
		t.Error("denial receipt must not leak the raw actor ID")
	}
	if !strings.Contains(body, "actor_hmac") {
		t.Errorf("denial receipt missing actor_hmac: %s", body)
	}
}

// TestHashActor_Properties: deterministic, key-separated, truncated hex.
func TestHashActor_Properties(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	h1 := HashActor(key, "actor")
	h2 := HashActor(key, "actor")
	if h1 != h2 {
		t.Error("HashActor must be deterministic")
	}
	if len(h1) != 32 { // 16 bytes hex-encoded
		t.Errorf("HashActor length = %d, want 32 hex chars", len(h1))
	}
	if HashActor(key, "other") == h1 {
		t.Error("different actors must hash differently")
	}
	derived := DeriveActorHashKey(key)
	if len(derived) != 32 {
		t.Errorf("DeriveActorHashKey length = %d, want 32", len(derived))
	}
	if HashActor(derived, "actor") == h1 {
		t.Error("derived key must produce a different digest than the raw key")
	}
	if hashActorID("actor") == "" {
		t.Error("hashActorID must return a digest")
	}
}
