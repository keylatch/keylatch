package broker

import (
	"context"
	"strings"
	"sync"
	"time"
)

// DefaultMaxCacheEntries caps the in-process tokenCache size. The bound
// prevents unbounded memory growth in scenarios with many distinct
// actor+provider+capability combinations (e.g. a large team where every
// member calls a different connection). The value is intentionally generous
// — 1000 entries at ~200 bytes each is ~200 KiB, well below any realistic
// memory pressure — while still being a hard ceiling so that a pathological
// key explosion cannot exhaust process memory.
const DefaultMaxCacheEntries = 1000

// cacheEntry is an in-memory cached token entry.
type cacheEntry struct {
	tokenBytes   []byte
	deadline     time.Time
	exchangeType ExchangeType
	// cacheAge tracks how long this entry has been in the cache.
	cacheAge time.Duration
	// insertedAt is when this entry was first cached.
	insertedAt time.Time
	// onEvict is called when the entry is evicted (for lease revocation).
	onEvict func()
}

// tokenCache is the in-process token store. Never written to disk.
//
// The cache is bounded: at most maxEntries live entries are kept. When a
// new entry is set and the cache is full, the entry with the oldest
// insertedAt timestamp is evicted (FIFO). FIFO is sufficient because
// tokens have a deadline-driven natural eviction path, and the bound is
// primarily a backstop against pathological growth — it is not the
// primary expiry mechanism.
type tokenCache struct {
	mu         sync.RWMutex
	entries    map[string]*cacheEntry
	maxEntries int
}

// NewTokenCache creates a tokenCache and starts a background eviction ticker.
// The ticker stops when ctx is cancelled. The cache uses DefaultMaxCacheEntries
// as its size bound; use NewTokenCacheWithLimit for a custom bound.
func NewTokenCache(ctx context.Context) *tokenCache {
	return NewTokenCacheWithLimit(ctx, DefaultMaxCacheEntries)
}

// NewTokenCacheWithLimit creates a tokenCache with an explicit size bound.
// A non-positive maxEntries falls back to DefaultMaxCacheEntries.
func NewTokenCacheWithLimit(ctx context.Context, maxEntries int) *tokenCache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxCacheEntries
	}
	c := &tokenCache{
		entries:    make(map[string]*cacheEntry),
		maxEntries: maxEntries,
	}
	go c.evictionLoop(ctx)
	return c
}

// evictionLoop removes expired entries every 30 seconds.
func (c *tokenCache) evictionLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// evictExpired removes entries whose deadline has passed.
func (c *tokenCache) evictExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.After(e.deadline) {
			zeroBytes(e.tokenBytes)
			if e.onEvict != nil {
				e.onEvict()
			}
			delete(c.entries, k)
		}
	}
}

// set stores an entry under key, overwriting any existing entry.
//
// When inserting a new key (not an overwrite) and the cache is at its
// maxEntries bound, the oldest entry (by insertedAt) is evicted first to
// make room. Token bytes are zeroed on eviction; onEvict callbacks (e.g.
// for lease revocation) fire before deletion.
func (c *tokenCache) set(key string, entry *cacheEntry) {
	if entry.insertedAt.IsZero() {
		entry.insertedAt = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.entries[key]; ok {
		// Overwrite: no size growth, just zero the old bytes.
		zeroBytes(old.tokenBytes)
		c.entries[key] = entry
		return
	}

	// New key. Enforce the size bound before insertion. Use >= so the
	// invariant after insertion is len(entries) <= maxEntries.
	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = entry
}

// evictOldestLocked removes the entry with the smallest insertedAt
// timestamp. Caller MUST hold c.mu in write mode. No-op if the cache
// is empty.
func (c *tokenCache) evictOldestLocked() {
	var (
		oldestKey   string
		oldestEntry *cacheEntry
	)
	for k, e := range c.entries {
		if oldestEntry == nil || e.insertedAt.Before(oldestEntry.insertedAt) {
			oldestKey = k
			oldestEntry = e
		}
	}
	if oldestEntry == nil {
		return
	}
	zeroBytes(oldestEntry.tokenBytes)
	if oldestEntry.onEvict != nil {
		oldestEntry.onEvict()
	}
	delete(c.entries, oldestKey)
}

// get returns a snapshot of the entry for key if it exists and has not expired.
// Returns a copy of cacheEntry so callers do not share the pointer with the cache.
func (c *tokenCache) get(key string) (*cacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.After(e.deadline) {
		// Expired — remove it.
		c.delete(key)
		return nil, false
	}
	// Return a shallow copy so callers do not race on the shared pointer.
	// Token bytes are shared read-only after insertion; they are only zeroed
	// under the write lock in delete/flush.
	snapshot := &cacheEntry{
		tokenBytes:   e.tokenBytes,
		deadline:     e.deadline,
		exchangeType: e.exchangeType,
		cacheAge:     now.Sub(e.insertedAt),
		insertedAt:   e.insertedAt,
		onEvict:      e.onEvict,
	}
	return snapshot, true
}

// delete removes the entry for key, zeroing its token bytes first.
func (c *tokenCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		zeroBytes(e.tokenBytes)
		if e.onEvict != nil {
			e.onEvict()
		}
		delete(c.entries, key)
	}
}

// flush zeroes all token bytes and clears all entries.
// Called synchronously on vault lock.
func (c *tokenCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		zeroBytes(e.tokenBytes)
		if e.onEvict != nil {
			e.onEvict()
		}
		delete(c.entries, k)
	}
}

// deleteBySession removes all entries whose key contains sessionID as a component.
// Uses null byte separator to match cacheKey construction (N-8).
func (c *tokenCache) deleteBySession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	marker := "\x00" + sessionID + "\x00"
	for k, e := range c.entries {
		if strings.Contains(k, marker) {
			zeroBytes(e.tokenBytes)
			if e.onEvict != nil {
				e.onEvict()
			}
			delete(c.entries, k)
		}
	}
}

// size returns the number of live (non-expired) entries.
func (c *tokenCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, e := range c.entries {
		if !now.After(e.deadline) {
			count++
		}
	}
	return count
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
