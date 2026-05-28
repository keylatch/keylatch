// Package broker implements the Phase 13 token broker for namespaced,
// short-lived credential exchange with in-memory caching.
//
// Security invariants:
//   - FIND2-004: OnVaultLock flushes cache synchronously before returning.
//   - Token bytes are carried in unexported fields and never appear in metadata.
//   - Audit events contain only HMAC-hashed actor/session IDs.
package broker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

// ExchangeType distinguishes fresh exchanges from cache hits.
type ExchangeType string

const (
	FreshExchange ExchangeType = "fresh_exchange"
	CacheHit      ExchangeType = "cache_hit"
)

// ExchangeResult is the public metadata returned from Exchange.
// Token bytes are carried internally and never exposed as a string field.
type ExchangeResult struct {
	Provider     string
	Capability   string
	CacheAge     time.Duration
	TTLRemaining time.Duration
	ExchangeType ExchangeType
	// tokenBytes are unexported; accessed via ScopedHandle only.
	tokenBytes []byte
}

// TokenBytes returns the raw token bytes for use in credential injection.
// Callers must zero the slice after use.
func (r *ExchangeResult) TokenBytes() []byte {
	cp := make([]byte, len(r.tokenBytes))
	copy(cp, r.tokenBytes)
	return cp
}

// Zero zeroes the token bytes in this result.
func (r *ExchangeResult) Zero() {
	for i := range r.tokenBytes {
		r.tokenBytes[i] = 0
	}
}

// NewExchangeResult constructs an ExchangeResult, copying src into an owned slice.
// After copying, src is zeroed so the caller's local buffer is cleared.
// The caller must not use src after calling this function.
func NewExchangeResult(provider, capability string, ttl time.Duration, exchangeType ExchangeType, src []byte) ExchangeResult {
	owned := make([]byte, len(src))
	copy(owned, src)
	// Zero src so the caller's local copy is cleared — owned is our copy.
	for i := range src {
		src[i] = 0
	}
	return ExchangeResult{
		Provider:     provider,
		Capability:   capability,
		TTLRemaining: ttl,
		ExchangeType: exchangeType,
		tokenBytes:   owned,
	}
}

// ExchangeStrategy is the interface all provider strategies implement.
type ExchangeStrategy interface {
	Exchange(ctx context.Context, actor, sessionID, namespace string) (ExchangeResult, error)
	Provider() string
}

// Broker is the public interface implemented by BrokerImpl.
type Broker interface {
	Exchange(ctx context.Context, actor, sessionID, provider, capability, namespace string) (ExchangeResult, error)
	Revoke(ctx context.Context, sessionID string) error
}

// Sentinel errors.
var (
	ErrVaultLocked         = errors.New("broker: vault is locked — all cached tokens flushed")
	ErrUnsupportedExchange = errors.New("broker: exchange strategy not supported for this provider")
	ErrMissingScopes       = errors.New("broker: required scopes not available for this capability")
	ErrExpiredRefreshToken = errors.New("broker: refresh token has expired or been revoked")
	ErrRevokedSession      = errors.New("broker: session has been revoked")
)

// BrokerImpl is the production implementation of Broker.
type BrokerImpl struct {
	cache        *tokenCache
	strategies   map[string]ExchangeStrategy // keyed by provider
	locked       atomic.Bool
	auditEmitter audit.Emitter
	hmacKey      []byte // for HMAC-hashing actor/session IDs in audit events
}

// NewBroker creates a new BrokerImpl with the provided strategies and audit emitter.
// It also sets the in-process singleton marker (see client.go) so that BrokerHandle
// callers can detect whether a broker is running in the current process.
func NewBroker(ctx context.Context, strategies map[string]ExchangeStrategy, auditEmitter audit.Emitter, hmacKey []byte) *BrokerImpl {
	b := &BrokerImpl{
		cache:        NewTokenCache(ctx),
		strategies:   strategies,
		auditEmitter: auditEmitter,
		hmacKey:      hmacKey,
	}
	markInProcess(b)
	return b
}

// Exchange returns a short-lived access token for the given actor/session/provider/capability/namespace.
// Cache hits are returned without calling the provider.
// FIND2-004: returns ErrVaultLocked when the vault is locked.
func (b *BrokerImpl) Exchange(ctx context.Context, actor, sessionID, provider, capability, namespace string) (ExchangeResult, error) {
	// 1. Check locked flag.
	if b.locked.Load() {
		return ExchangeResult{}, ErrVaultLocked
	}

	// 2. Build cache key.
	key := cacheKey(provider, capability, actor, sessionID, namespace)

	// 3. Check cache.
	if entry, ok := b.cache.get(key); ok {
		// Copy token bytes to isolate the caller's lifetime from the cache entry.
		tokenCopy := make([]byte, len(entry.tokenBytes))
		copy(tokenCopy, entry.tokenBytes)
		result := ExchangeResult{
			Provider:     provider,
			Capability:   capability,
			CacheAge:     entry.cacheAge,
			TTLRemaining: time.Until(entry.deadline),
			ExchangeType: CacheHit,
			tokenBytes:   tokenCopy,
		}
		b.emitCacheHit(ctx, actor, sessionID, provider, capability, entry)
		return result, nil
	}

	// 4. Cache miss: dispatch to strategy.
	strategy, ok := b.strategies[provider]
	if !ok {
		return ExchangeResult{}, ErrUnsupportedExchange
	}

	result, err := strategy.Exchange(ctx, actor, sessionID, namespace)
	if err != nil {
		return ExchangeResult{}, err
	}
	result.Provider = provider
	result.Capability = capability
	result.ExchangeType = FreshExchange

	// Cache the result.
	deadline := time.Now().Add(result.TTLRemaining)
	entry := &cacheEntry{
		tokenBytes:   result.tokenBytes,
		deadline:     deadline,
		exchangeType: FreshExchange,
		cacheAge:     0,
	}
	b.cache.set(key, entry)

	b.emitExchange(ctx, actor, sessionID, provider, capability, namespace, strategy, result)

	return result, nil
}

// Revoke removes all cached entries for the given sessionID.
func (b *BrokerImpl) Revoke(_ context.Context, sessionID string) error {
	b.cache.deleteBySession(sessionID)
	return nil
}

// emitExchange emits a broker.exchange audit event. Actor/session IDs are HMAC-hashed.
func (b *BrokerImpl) emitExchange(ctx context.Context, actor, sessionID, provider, capability, namespace string, strategy ExchangeStrategy, result ExchangeResult) {
	if b.auditEmitter == nil {
		return
	}
	// Use the typed struct to build the event, ensuring ScopesCount is populated
	// and schema stays in sync with BrokerExchangeEvent.
	evt := BrokerExchangeEvent{
		Provider:         provider,
		ExchangeStrategy: strategy.Provider(),
		ActorHMAC:        hashID(b.hmacKey, actor),
		SessionIDHMAC:    hashID(b.hmacKey, sessionID),
		Namespace:        namespace,
		Capability:       capability,
		TTLSeconds:       int64(result.TTLRemaining.Seconds()),
		ScopesCount:      0, // populated when scopes are tracked in a future phase
	}
	ev := audit.Event{
		Action:  audit.ActionBrokerExchange,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"provider":          evt.Provider,
			"exchange_strategy": evt.ExchangeStrategy,
			"actor_hmac":        evt.ActorHMAC,
			"session_id_hmac":   evt.SessionIDHMAC,
			"namespace":         evt.Namespace,
			"capability":        evt.Capability,
			"ttl_seconds":       evt.TTLSeconds,
			"scopes_count":      evt.ScopesCount,
		},
	}
	_ = b.auditEmitter.Emit(ctx, ev)
}

// emitCacheHit emits a broker.cache_hit audit event.
func (b *BrokerImpl) emitCacheHit(ctx context.Context, actor, sessionID, provider, capability string, entry *cacheEntry) {
	if b.auditEmitter == nil {
		return
	}
	ev := audit.Event{
		Action:  audit.ActionBrokerCacheHit,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"provider":              provider,
			"actor_hmac":            hashID(b.hmacKey, actor),
			"session_id_hmac":       hashID(b.hmacKey, sessionID),
			"capability":            capability,
			"cache_age_seconds":     int64(entry.cacheAge.Seconds()),
			"ttl_remaining_seconds": int64(time.Until(entry.deadline).Seconds()),
		},
	}
	_ = b.auditEmitter.Emit(ctx, ev)
}

// hashID returns a short HMAC-SHA256 hex digest of id using key.
func hashID(key []byte, id string) string {
	if len(key) == 0 {
		// No key: return a constant placeholder (do not leak id).
		return "no-hmac-key"
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// cacheKey builds the composite key for the token cache.
// Uses null byte as separator — none of the fields should contain null bytes,
// preventing key collisions from colon characters in field values.
func cacheKey(provider, capability, actor, sessionID, namespace string) string {
	return strings.Join([]string{provider, capability, actor, sessionID, namespace}, "\x00")
}
