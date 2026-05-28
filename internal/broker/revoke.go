package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

// ErrTokenNotFound is returned when the requested token ID does not exist in
// the broker cache. This covers both tokens that were never issued and tokens
// that have already expired or been revoked (removed from cache).
var ErrTokenNotFound = errors.New("broker: token not found — it may have already expired or been revoked")

// BrokerTokenRevokedEvent describes a token-revocation audit event.
// All actor/session identifiers are HMAC-hashed — no raw values.
type BrokerTokenRevokedEvent struct {
	TokenID                     string `json:"token_id"`
	Provider                    string `json:"provider"`
	ActorHMAC                   string `json:"actor_hmac"`
	Timestamp                   string `json:"timestamp"`
	ProviderRevocationAttempted bool   `json:"provider_revocation_attempted"`
	ProviderRevocationSucceeded bool   `json:"provider_revocation_succeeded"`
}

// Audit event action names for revoke operations.
const (
	// ActionBrokerTokenRevoked is emitted when a cached token is revoked.
	ActionBrokerTokenRevoked = "broker.token_revoked"
)

// revokeByTokenID finds the cache entry whose ScopedTokenID matches tokenID,
// removes it from the cache, attempts provider-side revocation (best-effort),
// and emits a BrokerTokenRevoked audit event.
//
// Returns ErrTokenNotFound if no live entry matches tokenID.
func revokeByTokenID(ctx context.Context, b *BrokerImpl, tokenID string) error {
	// Scan the cache for an entry matching the token ID.
	b.cache.mu.Lock()
	now := time.Now()
	var matchKey string
	var matchEntry *cacheEntry
	for key, entry := range b.cache.entries {
		if now.After(entry.deadline) {
			continue
		}
		if deriveScopedTokenID(b.hmacKey, key) == tokenID {
			matchKey = key
			matchEntry = entry
			break
		}
	}

	if matchKey == "" {
		b.cache.mu.Unlock()
		return ErrTokenNotFound
	}

	// Zero and delete the entry.
	zeroBytes(matchEntry.tokenBytes)
	if matchEntry.onEvict != nil {
		matchEntry.onEvict()
	}
	delete(b.cache.entries, matchKey)
	b.cache.mu.Unlock()

	// Extract metadata from key for the audit event.
	parts := splitKey(matchKey)
	provider := ""
	if len(parts) >= 1 {
		provider = parts[0]
	}
	actor := ""
	if len(parts) >= 3 {
		actor = parts[2]
	}
	actorHMAC := hashID(b.hmacKey, actor)

	// Attempt provider-side revocation (best-effort).
	// Future phases will check the provider template for a revocation endpoint.
	providerRevAttempted := false
	providerRevSucceeded := false
	// Provider revocation is template-driven; currently no templates declare
	// a revocation endpoint, so we skip the attempt and log accordingly.
	slog.Debug("broker: provider-side revocation not attempted — no revocation endpoint configured",
		"provider", provider, "token_id", tokenID)

	// Emit audit event.
	if b.auditEmitter != nil {
		evt := BrokerTokenRevokedEvent{
			TokenID:                     tokenID,
			Provider:                    provider,
			ActorHMAC:                   actorHMAC,
			Timestamp:                   time.Now().UTC().Format(time.RFC3339),
			ProviderRevocationAttempted: providerRevAttempted,
			ProviderRevocationSucceeded: providerRevSucceeded,
		}
		ev := audit.Event{
			Action:  ActionBrokerTokenRevoked,
			Outcome: audit.OutcomeOK,
			Extra: map[string]any{
				"token_id":                      evt.TokenID,
				"provider":                      evt.Provider,
				"actor_hmac":                    evt.ActorHMAC,
				"timestamp":                     evt.Timestamp,
				"provider_revocation_attempted": evt.ProviderRevocationAttempted,
				"provider_revocation_succeeded": evt.ProviderRevocationSucceeded,
			},
		}
		if err := b.auditEmitter.Emit(ctx, ev); err != nil {
			slog.Warn("broker: failed to emit token revoked audit event", "error", err)
		}
	}

	return nil
}

// revokeAllForActor revokes live cache entries for actorID.
//
// If actorID is empty (""), ALL live entries are revoked regardless of actor.
// If actorID is non-empty, only entries whose ActorHMAC matches the HMAC of
// actorID are revoked.
//
// Returns the count of entries successfully revoked.
// Races (entries that expire between snapshot and revocation) are tolerated
// silently — expired entries are simply skipped.
func revokeAllForActor(ctx context.Context, b *BrokerImpl, actorID string) (int, error) {
	// Collect matching token IDs from a snapshot.
	grants, err := (&inProcessHandle{b: b}).ListGrants()
	if err != nil {
		return 0, fmt.Errorf("broker: list grants: %w", err)
	}

	var tokenIDs []string
	if actorID == "" {
		// Revoke all grants regardless of actor.
		for _, g := range grants {
			tokenIDs = append(tokenIDs, g.ScopedTokenID)
		}
	} else {
		actorHMACTarget := hashID(b.hmacKey, actorID)
		for _, g := range grants {
			if g.ActorHMAC == actorHMACTarget {
				tokenIDs = append(tokenIDs, g.ScopedTokenID)
			}
		}
	}

	count := 0
	for _, tid := range tokenIDs {
		err := revokeByTokenID(ctx, b, tid)
		if err != nil {
			// Token may have expired between snapshot and revocation — skip.
			if errors.Is(err, ErrTokenNotFound) {
				continue
			}
			return count, fmt.Errorf("broker: revoke token %s: %w", tid, err)
		}
		count++
	}
	return count, nil
}
