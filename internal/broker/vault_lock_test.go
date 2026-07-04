package broker

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// mockStrategy is a simple ExchangeStrategy for testing.
type mockStrategy struct {
	provider string
	token    []byte
	ttl      time.Duration
}

func (m *mockStrategy) Provider() string { return m.provider }
func (m *mockStrategy) Exchange(_ context.Context, _, _, _ string) (ExchangeResult, error) {
	ttl := m.ttl
	if ttl == 0 {
		ttl = time.Hour
	}
	return ExchangeResult{
		TTLRemaining: ttl,
		ExchangeType: FreshExchange,
		tokenBytes:   append([]byte(nil), m.token...),
	}, nil
}

func newTestBroker(t *testing.T) *BrokerImpl {
	t.Helper()
	t.Cleanup(ResetInProcessSingleton)
	ctx := context.Background()
	strategies := map[string]ExchangeStrategy{
		"test-provider": &mockStrategy{
			provider: "test-provider",
			token:    []byte("mock-token"),
			ttl:      time.Hour,
		},
	}
	return NewBroker(ctx, strategies, nil, []byte("test-hmac-key-32-bytes-padding!!"))
}

func TestVaultLock_CacheFlushed(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	// Warm the cache.
	_, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("exchange before lock: %v", err)
	}

	if b.cache.size() == 0 {
		t.Fatal("expected cache to have an entry before lock")
	}

	// Lock.
	b.OnVaultLock(ctx)

	if b.cache.size() != 0 {
		t.Fatalf("expected cache to be empty after lock; got %d entries", b.cache.size())
	}
}

func TestVaultLock_ExchangeReturnsError(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	b.OnVaultLock(ctx)

	_, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked; got %v", err)
	}
}

func TestVaultUnlock_ExchangeProceeds(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	b.OnVaultLock(ctx)
	b.OnVaultUnlock(ctx)

	_, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("exchange after unlock: %v", err)
	}
}

func TestVaultLock_FlushSynchronous(t *testing.T) {
	// After OnVaultLock returns, the cache must be empty.
	b := newTestBroker(t)
	ctx := context.Background()

	// Prime cache with multiple distinct entries (N-5: use distinct keys per iteration).
	for i := 0; i < 5; i++ {
		key := cacheKey("test-provider", "cap", "actor", "sess", fmt.Sprintf("ns-%d", i))
		b.cache.set(key, &cacheEntry{
			tokenBytes:   []byte("tok"),
			deadline:     time.Now().Add(time.Hour),
			exchangeType: FreshExchange,
		})
	}

	b.OnVaultLock(ctx)

	// Flush must have happened before OnVaultLock returned.
	if b.cache.size() != 0 {
		t.Fatal("flush was not synchronous: cache still has entries after OnVaultLock returned")
	}
}
