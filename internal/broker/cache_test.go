package broker

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestCacheTTLExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	key := "provider:cap:actor:session:ns"

	c.set(key, &cacheEntry{
		tokenBytes:   []byte("tok"),
		deadline:     time.Now().Add(-1 * time.Millisecond), // already expired
		exchangeType: FreshExchange,
	})

	_, ok := c.get(key)
	if ok {
		t.Fatal("expected cache miss for expired entry")
	}
}

func TestCacheNamespaceSeparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	dl := time.Now().Add(1 * time.Hour)

	keyA := cacheKey("prov", "cap", "actor", "sess", "ns-a")
	keyB := cacheKey("prov", "cap", "actor", "sess", "ns-b")

	c.set(keyA, &cacheEntry{tokenBytes: []byte("tokenA"), deadline: dl, exchangeType: FreshExchange})
	c.set(keyB, &cacheEntry{tokenBytes: []byte("tokenB"), deadline: dl, exchangeType: FreshExchange})

	eA, okA := c.get(keyA)
	eB, okB := c.get(keyB)

	if !okA || !okB {
		t.Fatal("expected both namespace entries to be present")
	}
	if string(eA.tokenBytes) == string(eB.tokenBytes) {
		t.Fatal("namespace entries should be distinct")
	}
}

func TestCacheFlushZerosTokenBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	tok := []byte("secret-token-data")
	key := "prov:cap:actor:sess:ns"

	entry := &cacheEntry{
		tokenBytes:   tok,
		deadline:     time.Now().Add(1 * time.Hour),
		exchangeType: FreshExchange,
	}
	c.set(key, entry)

	c.flush()

	// After flush, all bytes in the original slice must be zero.
	for i, b := range tok {
		if b != 0 {
			t.Fatalf("byte[%d] not zeroed after flush: got %d", i, b)
		}
	}

	if _, ok := c.get(key); ok {
		t.Fatal("entry should be absent after flush")
	}
}

func TestCacheEvictionStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	c := NewTokenCache(ctx)
	_ = c

	// Cancel context — the eviction goroutine must stop.
	cancel()

	// Assert the goroutine exits within a concrete timeout.
	done := make(chan struct{})
	go func() {
		// Write a new entry after cancel — if the eviction goroutine is still running
		// and racing on the map, the race detector will catch it.
		c.set("test-key-after-cancel", &cacheEntry{
			tokenBytes:   []byte("tok"),
			deadline:     time.Now().Add(time.Hour),
			exchangeType: FreshExchange,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("eviction goroutine did not stop within 200ms of context cancellation")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	dl := time.Now().Add(1 * time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := cacheKey("prov", "cap", "actor", "sess", "ns")
			c.set(key, &cacheEntry{
				tokenBytes:   []byte("tok"),
				deadline:     dl,
				exchangeType: FreshExchange,
			})
			c.get(key)
			c.deleteBySession("sess")
		}(i)
	}
	wg.Wait()
}

func TestCacheDeleteBySession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	dl := time.Now().Add(1 * time.Hour)

	key1 := cacheKey("prov", "cap", "actor", "sess-A", "ns")
	key2 := cacheKey("prov", "cap", "actor", "sess-B", "ns")

	c.set(key1, &cacheEntry{tokenBytes: []byte("tokA"), deadline: dl, exchangeType: FreshExchange})
	c.set(key2, &cacheEntry{tokenBytes: []byte("tokB"), deadline: dl, exchangeType: FreshExchange})

	c.deleteBySession("sess-A")

	if _, ok := c.get(key1); ok {
		t.Fatal("sess-A entry should have been deleted")
	}
	if _, ok := c.get(key2); !ok {
		t.Fatal("sess-B entry should still be present")
	}
}

// TestCacheMaxEntries_EvictsOldestOnInsert asserts that when the cache is
// at its maxEntries bound, inserting a new key evicts the entry with the
// oldest insertedAt timestamp (FIFO). This prevents pathological memory
// growth in scenarios with many distinct actor+provider+capability keys.
func TestCacheMaxEntries_EvictsOldestOnInsert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tiny bound so the test is fast and the oldest entry is unambiguous.
	const limit = 3
	c := NewTokenCacheWithLimit(ctx, limit)

	dl := time.Now().Add(1 * time.Hour)
	base := time.Now().Add(-time.Hour)

	// Insert three entries with explicit, monotonically increasing
	// insertedAt timestamps. "k0" is the oldest.
	for i := 0; i < limit; i++ {
		key := cacheKey("prov", "cap", "actor", "sess", "ns"+string(rune('0'+i)))
		c.set(key, &cacheEntry{
			tokenBytes:   []byte{byte('A' + i)},
			deadline:     dl,
			exchangeType: FreshExchange,
			insertedAt:   base.Add(time.Duration(i) * time.Minute),
		})
	}
	if got := c.size(); got != limit {
		t.Fatalf("expected size=%d after initial fill; got %d", limit, got)
	}

	// Insert one more entry. The cache must evict "k0" — the oldest.
	overflowKey := cacheKey("prov", "cap", "actor", "sess", "overflow")
	c.set(overflowKey, &cacheEntry{
		tokenBytes:   []byte("OVF"),
		deadline:     dl,
		exchangeType: FreshExchange,
		insertedAt:   base.Add(time.Duration(limit) * time.Minute),
	})

	// Total size must still equal limit.
	if got := c.size(); got != limit {
		t.Fatalf("cache size must equal limit after eviction; want %d got %d", limit, got)
	}

	// The oldest key (ns0) must be gone.
	oldestKey := cacheKey("prov", "cap", "actor", "sess", "ns0")
	if _, ok := c.get(oldestKey); ok {
		t.Errorf("oldest entry (ns0) should have been evicted; still present")
	}

	// The newest and middle keys must still be present.
	for _, ns := range []string{"ns1", "ns2", "overflow"} {
		k := cacheKey("prov", "cap", "actor", "sess", ns)
		if _, ok := c.get(k); !ok {
			t.Errorf("entry %q should still be present after eviction", ns)
		}
	}
}

// TestCacheMaxEntries_OverwriteDoesNotEvict asserts that overwriting an
// existing key does not trigger eviction even when the cache is full.
// Overwrite must zero the old token bytes but keep size unchanged.
func TestCacheMaxEntries_OverwriteDoesNotEvict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const limit = 2
	c := NewTokenCacheWithLimit(ctx, limit)

	dl := time.Now().Add(time.Hour)
	keyA := cacheKey("prov", "cap", "actor", "sess", "A")
	keyB := cacheKey("prov", "cap", "actor", "sess", "B")

	c.set(keyA, &cacheEntry{tokenBytes: []byte("tokA"), deadline: dl, insertedAt: time.Now().Add(-2 * time.Minute)})
	c.set(keyB, &cacheEntry{tokenBytes: []byte("tokB"), deadline: dl, insertedAt: time.Now().Add(-time.Minute)})

	if got := c.size(); got != 2 {
		t.Fatalf("initial size=%d; want 2", got)
	}

	// Overwrite A — even though the cache is full, no eviction must occur.
	c.set(keyA, &cacheEntry{tokenBytes: []byte("tokA2"), deadline: dl, insertedAt: time.Now()})

	if got := c.size(); got != 2 {
		t.Fatalf("size after overwrite must remain 2; got %d", got)
	}
	// Both keys still present.
	if _, ok := c.get(keyA); !ok {
		t.Error("overwritten key A must still be present")
	}
	if _, ok := c.get(keyB); !ok {
		t.Error("key B must not have been evicted by an overwrite")
	}
}

// TestCacheMaxEntries_DefaultLimitApplied asserts that NewTokenCache uses
// DefaultMaxCacheEntries as its bound.
func TestCacheMaxEntries_DefaultLimitApplied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCache(ctx)
	if c.maxEntries != DefaultMaxCacheEntries {
		t.Errorf("NewTokenCache should use DefaultMaxCacheEntries (%d); got %d",
			DefaultMaxCacheEntries, c.maxEntries)
	}
}

// TestCacheMaxEntries_NonPositiveFallsBackToDefault asserts that
// NewTokenCacheWithLimit ignores zero or negative limits and uses the
// default. This guards against a caller accidentally disabling the bound.
func TestCacheMaxEntries_NonPositiveFallsBackToDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, lim := range []int{0, -1, -1000} {
		c := NewTokenCacheWithLimit(ctx, lim)
		if c.maxEntries != DefaultMaxCacheEntries {
			t.Errorf("limit %d should fall back to default %d; got %d",
				lim, DefaultMaxCacheEntries, c.maxEntries)
		}
	}
}

// TestCacheMaxEntries_OnEvictFires asserts that the onEvict callback runs
// when an entry is forcibly evicted to make room for a new key.
func TestCacheMaxEntries_OnEvictFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewTokenCacheWithLimit(ctx, 1)
	dl := time.Now().Add(time.Hour)

	var (
		evicted int32
		mu      sync.Mutex
	)
	c.set("k1", &cacheEntry{
		tokenBytes: []byte("k1tok"),
		deadline:   dl,
		insertedAt: time.Now().Add(-time.Minute),
		onEvict: func() {
			mu.Lock()
			evicted++
			mu.Unlock()
		},
	})
	c.set("k2", &cacheEntry{
		tokenBytes: []byte("k2tok"),
		deadline:   dl,
		insertedAt: time.Now(),
	})

	mu.Lock()
	defer mu.Unlock()
	if evicted != 1 {
		t.Errorf("onEvict callback must fire on size-driven eviction; fired %d times", evicted)
	}
}
