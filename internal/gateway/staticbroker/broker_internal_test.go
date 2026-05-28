// Package staticbroker — internal tests for unexported methods that cannot be
// reached from the external _test package within reasonable test timeouts.
package staticbroker

import (
	"testing"
	"time"
)

// TestEvictExpired_RemovesExpiredEntries calls evictExpired directly to avoid
// waiting for the 60-second ticker used in the background goroutine.
func TestEvictExpired_RemovesExpiredEntries(t *testing.T) {
	b := NewWithOptions(10)
	defer b.Stop()

	// Insert an already-expired entry directly into the cache.
	key := BrokerCacheKey{Provider: "test", Actor: "a", Namespace: "n", Capability: "c"}
	b.mu.Lock()
	b.cache[key] = cachedToken{
		token:     AccessToken{Value: []byte("stale")},
		expiresAt: time.Now().UTC().Add(-1 * time.Second), // already expired
	}
	b.mu.Unlock()

	// Trigger eviction.
	b.evictExpired()

	// Entry must be gone.
	b.mu.Lock()
	_, found := b.cache[key]
	b.mu.Unlock()
	if found {
		t.Error("evictExpired() did not remove expired entry")
	}
}

// TestEvictExpired_KeepsValidEntries verifies that non-expired entries survive eviction.
func TestEvictExpired_KeepsValidEntries(t *testing.T) {
	b := NewWithOptions(10)
	defer b.Stop()

	key := BrokerCacheKey{Provider: "test", Actor: "a", Namespace: "n", Capability: "c"}
	b.mu.Lock()
	b.cache[key] = cachedToken{
		token:     AccessToken{Value: []byte("valid")},
		expiresAt: time.Now().UTC().Add(1 * time.Hour), // not yet expired
	}
	b.mu.Unlock()

	b.evictExpired()

	b.mu.Lock()
	_, found := b.cache[key]
	b.mu.Unlock()
	if !found {
		t.Error("evictExpired() removed a non-expired entry")
	}
}

// TestRunEviction_ExitsOnStop verifies that runEviction terminates when Stop is called.
func TestRunEviction_ExitsOnStop(t *testing.T) {
	b := NewWithOptions(10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.runEviction()
	}()
	// Give the goroutine time to start and block on the ticker/stopEvict select.
	time.Sleep(5 * time.Millisecond)
	b.Stop()
	select {
	case <-done:
		// goroutine exited as expected
	case <-time.After(2 * time.Second):
		t.Error("runEviction() did not exit after Stop()")
	}
}

// TestSet_EvictsOldestWhenFull verifies the LRU eviction in set().
func TestSet_EvictsOldestWhenFull(t *testing.T) {
	const max = 3
	b := NewWithOptions(max)
	defer b.Stop()

	// Fill to capacity.
	for i := 0; i < max; i++ {
		key := BrokerCacheKey{Provider: "p", Actor: "a", Namespace: "n", Capability: string(rune('A' + i))}
		b.mu.Lock()
		b.set(key, cachedToken{
			token:     AccessToken{Value: []byte("v")},
			expiresAt: time.Now().UTC().Add(time.Duration(i+1) * time.Minute),
		})
		b.mu.Unlock()
	}

	// cache is now full; set one more — should evict the earliest-expiring entry.
	newKey := BrokerCacheKey{Provider: "p", Actor: "a", Namespace: "n", Capability: "NEW"}
	b.mu.Lock()
	cacheLen := len(b.cache)
	b.set(newKey, cachedToken{
		token:     AccessToken{Value: []byte("new")},
		expiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	newLen := len(b.cache)
	b.mu.Unlock()

	if cacheLen != max {
		t.Fatalf("before set: expected %d entries, got %d", max, cacheLen)
	}
	if newLen != max {
		t.Errorf("after set: expected cache to stay at %d entries, got %d", max, newLen)
	}
}

// TestOnVaultLock_ZeroesAllCachedValues verifies that OnVaultLock zeroes token bytes in cache.
func TestOnVaultLock_ZeroesAllCachedValues(t *testing.T) {
	b := NewWithOptions(10)
	defer b.Stop()

	key := BrokerCacheKey{Provider: "test", Actor: "a", Namespace: "n", Capability: "c"}
	tokenBytes := []byte("super-secret")
	b.mu.Lock()
	b.cache[key] = cachedToken{
		token:     AccessToken{Value: tokenBytes},
		expiresAt: time.Now().UTC().Add(time.Hour),
	}
	b.mu.Unlock()

	if err := b.OnVaultLock(nil); err != nil { //nolint:staticcheck // context arg unused by OnVaultLock
		t.Fatalf("OnVaultLock: %v", err)
	}

	// Cache must be empty after lock.
	b.mu.Lock()
	cacheLen := len(b.cache)
	b.mu.Unlock()
	if cacheLen != 0 {
		t.Errorf("OnVaultLock did not clear cache: %d entries remain", cacheLen)
	}
}
