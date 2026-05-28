// Package staticbroker implements the Phase 9 static token broker for
// the gateway's credential exchange layer.
//
// Rationale (ADR-002): internal/broker (Phase 13) has a strategy-based,
// actor/session-keyed API incompatible with the gateway's flat ExchangeSpec
// contract. Rather than merging two fundamentally different APIs prematurely,
// this package is renamed from internal/gateway/broker to
// internal/gateway/staticbroker to clarify its role as a Phase 9 stopgap.
// Full unification is deferred to Phase 13 when internal/broker matures.
//
// Security invariants:
//   - S9-17: the in-process cache is never written to disk.
//   - FIND2-004: OnVaultLock zeroes and purges all cached tokens.
package staticbroker

import (
	"context"
	"errors"
	"sync"
	"time"
)

// defaultMaxEntries is the default maximum number of cached entries.
const defaultMaxEntries = 500

// evictionInterval is how often the background goroutine sweeps expired entries.
const evictionInterval = 60 * time.Second

// Sentinel errors.
var (
	ErrExchangeUnsupported = errors.New("broker: exchange strategy unsupported in Phase 9")
	ErrScopesInsufficient  = errors.New("broker: insufficient scopes")
	ErrVaultLocked         = errors.New("broker: vault is locked")
)

// ExchangeSpec is the input to Exchange.
type ExchangeSpec struct {
	Strategy       string // registry.ExchangeStrategy value
	RootCredential []byte
	Actor          string
	Capability     string
	Namespace      string
	TTL            time.Duration
}

// AccessToken is the output of Exchange.
type AccessToken struct {
	Value     []byte
	ExpiresAt time.Time
	Metadata  map[string]string
}

// Zero zeroes the credential bytes in the AccessToken (S9-2).
func (a *AccessToken) Zero() {
	for i := range a.Value {
		a.Value[i] = 0
	}
}

// BrokerCacheKey is the cache key for exchanged tokens.
// S9-17: cache is in-process only, never written to disk.
type BrokerCacheKey struct {
	Provider   string
	Actor      string
	Namespace  string
	Capability string
}

// cachedToken is an in-memory cached access token entry.
type cachedToken struct {
	token     AccessToken
	expiresAt time.Time
}

// Broker implements in-process access-token exchange and caching.
// S9-17: cache is in-process only, never written to disk.
type Broker struct {
	mu         sync.Mutex
	cache      map[BrokerCacheKey]cachedToken
	maxEntries int
	locked     bool // FIND2-004: set true by OnVaultLock
	stopEvict  chan struct{}
}

// New creates a new Broker instance with bounded cache and background eviction.
func New() *Broker {
	return NewWithOptions(defaultMaxEntries)
}

// NewWithOptions creates a Broker with an explicit max-entries limit.
// It does NOT start the background eviction goroutine; call Start(ctx) to begin eviction.
func NewWithOptions(maxEntries int) *Broker {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	b := &Broker{
		cache:      make(map[BrokerCacheKey]cachedToken),
		maxEntries: maxEntries,
		stopEvict:  make(chan struct{}),
	}
	return b
}

// Start starts the background eviction goroutine, stopping when ctx is done or Stop is called.
// Must be called at most once per Broker instance; NewWithOptions does not start it automatically.
func (b *Broker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(evictionInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-b.stopEvict:
				return
			case <-ticker.C:
				b.evictExpired()
			}
		}
	}()
}

// Stop signals the background eviction goroutine to exit.
func (b *Broker) Stop() {
	select {
	case b.stopEvict <- struct{}{}:
	default:
	}
}

func (b *Broker) runEviction() {
	ticker := time.NewTicker(evictionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopEvict:
			return
		case <-ticker.C:
			b.evictExpired()
		}
	}
}

func (b *Broker) evictExpired() {
	now := time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, ct := range b.cache {
		if ct.expiresAt.Before(now) {
			ct.token.Zero()
			delete(b.cache, key)
		}
	}
}

func (b *Broker) set(key BrokerCacheKey, ct cachedToken) { //nolint:unused // planned: used by token refresh path in Phase 13 broker cache
	if len(b.cache) >= b.maxEntries {
		var (
			evictKey    BrokerCacheKey
			evictExpiry time.Time
			first       = true
		)
		for k, v := range b.cache {
			if first || v.expiresAt.Before(evictExpiry) {
				evictKey = k
				evictExpiry = v.expiresAt
				first = false
			}
		}
		if old, ok := b.cache[evictKey]; ok {
			old.token.Zero()
		}
		delete(b.cache, evictKey)
	}
	b.cache[key] = ct
}

// Exchange exchanges a root credential for a short-lived access token.
//
// Phase 9 handles:
//   - "static_gateway_only": returns root credential as-is.
//   - "none": returns empty access token.
//
// All other strategies return ErrExchangeUnsupported.
func (b *Broker) Exchange(ctx context.Context, spec ExchangeSpec) (AccessToken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.locked {
		return AccessToken{}, ErrVaultLocked
	}

	switch spec.Strategy {
	case "static_gateway_only", "":
		val := make([]byte, len(spec.RootCredential))
		copy(val, spec.RootCredential)
		ttl := spec.TTL
		if ttl <= 0 {
			ttl = 1 * time.Hour
		}
		return AccessToken{
			Value:     val,
			ExpiresAt: time.Now().UTC().Add(ttl),
			Metadata:  map[string]string{"strategy": "static_gateway_only"},
		}, nil

	case "none":
		return AccessToken{
			Value:     nil,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
			Metadata:  map[string]string{"strategy": "none"},
		}, nil

	default:
		return AccessToken{}, ErrExchangeUnsupported
	}
}

// Revoke purges cached entry for the given key.
func (b *Broker) Revoke(_ context.Context, key BrokerCacheKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ct, ok := b.cache[key]; ok {
		ct.token.Zero()
	}
	delete(b.cache, key)
	return nil
}

// DryRun returns metadata about what Exchange would do without doing it.
func (b *Broker) DryRun(_ context.Context, spec ExchangeSpec) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.locked {
		return nil, ErrVaultLocked
	}

	switch spec.Strategy {
	case "static_gateway_only", "":
		return map[string]string{
			"strategy":         "static_gateway_only",
			"would_exchange":   "false",
			"credential_shape": "root_as_is",
		}, nil
	case "none":
		return map[string]string{
			"strategy":         "none",
			"would_exchange":   "false",
			"credential_shape": "empty",
		}, nil
	default:
		return map[string]string{
			"strategy":    spec.Strategy,
			"supported":   "false",
			"phase":       "13",
			"remediation": "Upgrade to Phase 13 for dynamic exchange strategies. Static gateway mode is available now.",
		}, ErrExchangeUnsupported
	}
}

// OnVaultLock zeroes and purges all cached tokens.
// FIND2-004.
func (b *Broker) OnVaultLock(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, ct := range b.cache {
		ct.token.Zero()
		delete(b.cache, key)
	}
	b.locked = true
	return nil
}

// OnVaultUnlock clears the locked flag.
func (b *Broker) OnVaultUnlock(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.locked = false
	return nil
}
