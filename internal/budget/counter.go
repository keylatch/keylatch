package budget

import (
	"context"
	"sync"
	"time"
)

// windowBucket tracks usage within a sliding time window.
type windowBucket struct {
	total     float64
	windowEnd time.Time
	duration  time.Duration
	limit     float64
}

// isExpired returns true if the window has elapsed.
func (b *windowBucket) isExpired(now time.Time) bool {
	return now.After(b.windowEnd)
}

// budgetKey identifies a (actor, capability, limitType) tuple.
type budgetKey struct {
	actor      string
	capability string
	limitType  string
}

// InMemoryBudgetCounter implements BudgetCounter with a sliding window per key.
type InMemoryBudgetCounter struct {
	mu           sync.Mutex
	windows      map[budgetKey]*windowBucket
	policy       BudgetPolicy
	evictionDone chan struct{} // closed when eviction goroutine exits
}

// NewInMemoryBudgetCounter creates a counter with the given policy.
// The eviction goroutine is tied to ctx — cancel ctx to stop it cleanly (M-1).
func NewInMemoryBudgetCounter(ctx context.Context, policy BudgetPolicy) *InMemoryBudgetCounter {
	c := &InMemoryBudgetCounter{
		windows:      make(map[budgetKey]*windowBucket),
		policy:       policy,
		evictionDone: make(chan struct{}),
	}
	go c.evictionLoop(ctx)
	return c
}

// evictionLoop periodically removes expired windows and stops when ctx is cancelled (M-1).
func (c *InMemoryBudgetCounter) evictionLoop(ctx context.Context) {
	defer close(c.evictionDone)
	ticker := time.NewTicker(60 * time.Second)
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

// evictExpired removes buckets whose window has elapsed.
func (c *InMemoryBudgetCounter) evictExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, b := range c.windows {
		if b.isExpired(now) {
			delete(c.windows, k)
		}
	}
}

// Check returns ErrBudgetExceeded if adding amount would exceed any configured limit.
// This is a read-only check (no reservation) — use CheckAndRecord for atomic enforcement.
func (c *InMemoryBudgetCounter) Check(_ context.Context, actor, capability string, amount float64) error {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, kv := range c.relevantKeys(actor, capability) {
		b, ok := c.windows[kv.key]
		if !ok || b.isExpired(now) {
			continue // fresh window — not at limit
		}
		if b.total+amount > kv.limit {
			return ErrBudgetExceeded
		}
	}
	return nil
}

// CheckAndRecord atomically checks the budget and records the usage in one locked operation.
// This eliminates the TOCTOU race between separate Check + Record calls (C-4).
// On success the usage is recorded; on ErrBudgetExceeded no usage is recorded.
func (c *InMemoryBudgetCounter) CheckAndRecord(_ context.Context, actor, capability string, amount float64) error {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Phase 1: check all windows under write lock.
	for _, kv := range c.relevantKeys(actor, capability) {
		b, ok := c.windows[kv.key]
		if !ok || b.isExpired(now) {
			continue // fresh window — not at limit yet
		}
		if b.total+amount > kv.limit {
			return ErrBudgetExceeded
		}
	}

	// Phase 2: record atomically (still under the same write lock).
	c.recordLocked(now, actor, capability, amount)
	return nil
}

// Record increments usage for all relevant windows.
// Prefer CheckAndRecord for gateway enforcement to avoid TOCTOU.
func (c *InMemoryBudgetCounter) Record(_ context.Context, actor, capability string, amount float64) error {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordLocked(now, actor, capability, amount)
	return nil
}

// recordLocked increments the windows for actor/capability. Must be called under c.mu.
func (c *InMemoryBudgetCounter) recordLocked(now time.Time, actor, capability string, amount float64) {
	for _, kv := range c.relevantKeys(actor, capability) {
		b, ok := c.windows[kv.key]
		if !ok || b.isExpired(now) {
			// Start a new window.
			b = &windowBucket{
				duration:  kv.window,
				windowEnd: now.Add(kv.window),
				limit:     kv.limit,
			}
			c.windows[kv.key] = b
		}
		b.total += amount
	}
}

// relevantKey pairs a budgetKey with its limit and window for policy iteration.
type relevantKey struct {
	key    budgetKey
	limit  float64
	window time.Duration
}

// relevantKeys returns all configured limit keys for an (actor, capability) pair.
func (c *InMemoryBudgetCounter) relevantKeys(actor, capability string) []relevantKey {
	var keys []relevantKey

	if c.policy.SpendPerHour > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "spend_per_hour"},
			limit:  c.policy.SpendPerHour,
			window: time.Hour,
		})
	}
	if c.policy.SpendPerDay > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "spend_per_day"},
			limit:  c.policy.SpendPerDay,
			window: 24 * time.Hour,
		})
	}
	if c.policy.EmailSendsPerHour > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "email_sends_per_hour"},
			limit:  float64(c.policy.EmailSendsPerHour),
			window: time.Hour,
		})
	}
	if c.policy.SlackMessagesPerHour > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "slack_messages_per_hour"},
			limit:  float64(c.policy.SlackMessagesPerHour),
			window: time.Hour,
		})
	}
	if c.policy.DNSMutationsPerDay > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "dns_mutations_per_day"},
			limit:  float64(c.policy.DNSMutationsPerDay),
			window: 24 * time.Hour,
		})
	}
	if c.policy.AWSActionCount > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "aws_action_count"},
			limit:  float64(c.policy.AWSActionCount),
			window: 24 * time.Hour,
		})
	}
	if c.policy.StripeRefundAmount > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "stripe_refund_amount"},
			limit:  c.policy.StripeRefundAmount,
			window: 24 * time.Hour,
		})
	}
	if c.policy.DownloadBytesLimit > 0 {
		keys = append(keys, relevantKey{
			key:    budgetKey{actor, capability, "download_bytes"},
			limit:  float64(c.policy.DownloadBytesLimit),
			window: 24 * time.Hour,
		})
	}

	return keys
}
