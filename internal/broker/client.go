package broker

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// ErrBrokerOutOfProcess is returned by every BrokerHandle method when the
// broker is not running in-process. The message is intentionally actionable:
// it tells the operator exactly which process owns the broker and how to
// interact with it.
var ErrBrokerOutOfProcess = errors.New(
	"broker: not running in-process — " +
		"this CLI invocation does not own the broker; " +
		"use the gateway process (keylatch gateway up) to exchange or revoke tokens, " +
		"or run this command from within the same process that constructed the broker",
)

// Grant is a value-free snapshot of a single live cache entry.
// Token bytes are never included — only metadata safe to expose on the CLI.
type Grant struct {
	// Provider is the provider slug (e.g. "openrouter", "github").
	Provider string
	// ActorHMAC is the HMAC-hashed actor ID (not the raw actor string).
	ActorHMAC string
	// ScopedTokenID is a stable, opaque identifier for the cached token entry.
	// It is derived from the cache key — never the raw token bytes.
	ScopedTokenID string
	// ExpiresAt is the deadline of the cached entry.
	ExpiresAt time.Time
	// InsertedAt is when the entry was first stored in the cache.
	InsertedAt time.Time
}

// DryRunResult is the value-free result of a simulated token exchange.
// No provider token endpoint is called; no cache is mutated.
type DryRunResult struct {
	// Provider is the provider slug.
	Provider string
	// ScopesRequested is the list of scopes the command would request.
	// May be empty if the template does not declare command-scope mappings.
	ScopesRequested []string
	// ScopedTokenTTL is the TTL the exchange would request from the provider.
	ScopedTokenTTL time.Duration
	// PolicyDecision is "allow" or "deny".
	PolicyDecision string
	// Reason is a human-readable explanation of the policy decision.
	Reason string
}

// BrokerHandle is the interface through which CLI commands interact with the
// in-process broker. All methods are value-free — no token bytes are returned.
//
// Out-of-process handles return ErrBrokerOutOfProcess from every method.
type BrokerHandle interface {
	// ListGrants returns a snapshot of all live (non-expired) cache entries.
	// No token bytes are included.
	ListGrants() ([]*Grant, error)

	// DryRunExchange simulates a token exchange for the given provider and
	// command without calling the provider endpoint or mutating the cache.
	// It reads the provider template, derives scopes from the command string,
	// runs the policy check, and returns a DryRunResult.
	DryRunExchange(provider, command string) (*DryRunResult, error)

	// Revoke marks the token identified by tokenID as revoked, evicts it from
	// the cache, and attempts provider-side revocation if the template declares
	// a revocation endpoint (best-effort; logs on failure).
	Revoke(tokenID string) error

	// RevokeAll revokes all active grants for actorID.
	// Returns the count of grants that were successfully revoked.
	// Races (entries already expired between ListGrants and Revoke) are
	// tolerated silently.
	RevokeAll(actorID string) (count int, err error)
}

// inProcessMarker is set to 1 when a BrokerImpl is constructed, indicating
// that a broker is running in this process.
var inProcessMarker atomic.Int32

// currentBroker is the most-recently-constructed BrokerImpl in this process.
// It is set by markInProcess and read by NewBrokerHandle(nil).
// Protected by atomic pointer swap — safe for concurrent reads after init.
var currentBrokerPtr atomic.Pointer[BrokerImpl]

// IsBrokerInProcess reports whether a BrokerImpl has been constructed in this
// process. Used by NewBrokerHandle to decide which concrete handle to return.
func IsBrokerInProcess() bool {
	return inProcessMarker.Load() != 0
}

// CurrentBroker returns the most-recently-constructed BrokerImpl, or nil if
// no broker has been constructed in this process.
func CurrentBroker() *BrokerImpl {
	return currentBrokerPtr.Load()
}

// markInProcess sets the in-process singleton marker and stores b. Called by NewBroker.
func markInProcess(b *BrokerImpl) {
	inProcessMarker.Store(1)
	currentBrokerPtr.Store(b)
}

// NewBrokerHandle returns a BrokerHandle for use by CLI commands.
//
// If b is non-nil, it is used directly (explicit in-process handle).
//
// If b is nil, the function checks whether a BrokerImpl was constructed in
// this process (via the singleton set in NewBroker). If so, an inProcessHandle
// backed by the current broker is returned. Otherwise, an outOfProcessHandle
// is returned that returns ErrBrokerOutOfProcess from every method.
//
// This is the primary constructor for CLI commands that do not hold a direct
// reference to a *BrokerImpl.
func NewBrokerHandle(b *BrokerImpl) BrokerHandle {
	if b != nil {
		return &inProcessHandle{b: b}
	}
	if cur := CurrentBroker(); cur != nil {
		return &inProcessHandle{b: cur}
	}
	return &outOfProcessHandle{}
}

// ─── in-process handle ───────────────────────────────────────────────────────

// inProcessHandle delegates to a live BrokerImpl.
type inProcessHandle struct {
	b *BrokerImpl
}

// ListGrants returns a snapshot of all live cache entries.
func (h *inProcessHandle) ListGrants() ([]*Grant, error) {
	h.b.cache.mu.RLock()
	defer h.b.cache.mu.RUnlock()

	now := time.Now()
	var grants []*Grant
	for key, entry := range h.b.cache.entries {
		if now.After(entry.deadline) {
			continue
		}
		provider := extractProviderFromKey(key)
		actorHMAC := hashID(h.b.hmacKey, extractActorFromKey(key))
		g := &Grant{
			Provider:      provider,
			ActorHMAC:     actorHMAC,
			ScopedTokenID: deriveScopedTokenID(h.b.hmacKey, key),
			ExpiresAt:     entry.deadline,
			InsertedAt:    entry.insertedAt,
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// DryRunExchange simulates a token exchange. Does not call the provider or
// mutate the cache.
func (h *inProcessHandle) DryRunExchange(provider, command string) (*DryRunResult, error) {
	return dryRunExchange(h.b, provider, command)
}

// Revoke removes the cache entry for tokenID and emits a BrokerTokenRevoked
// audit event.
func (h *inProcessHandle) Revoke(tokenID string) error {
	return revokeByTokenID(context.Background(), h.b, tokenID)
}

// RevokeAll revokes all active grants and returns the count of revoked entries.
func (h *inProcessHandle) RevokeAll(actorID string) (int, error) {
	return revokeAllForActor(context.Background(), h.b, actorID)
}

// NewOutOfProcessHandle returns a BrokerHandle that always returns
// ErrBrokerOutOfProcess from every method. Intended for testing and for
// situations where the caller knows the broker is not available in-process.
func NewOutOfProcessHandle() BrokerHandle {
	return &outOfProcessHandle{}
}

// ─── out-of-process handle ───────────────────────────────────────────────────

// outOfProcessHandle is returned when no BrokerImpl was constructed in this
// process. Every method returns ErrBrokerOutOfProcess.
type outOfProcessHandle struct{}

func (h *outOfProcessHandle) ListGrants() ([]*Grant, error) {
	return nil, ErrBrokerOutOfProcess
}

func (h *outOfProcessHandle) DryRunExchange(_, _ string) (*DryRunResult, error) {
	return nil, ErrBrokerOutOfProcess
}

func (h *outOfProcessHandle) Revoke(_ string) error {
	return ErrBrokerOutOfProcess
}

func (h *outOfProcessHandle) RevokeAll(_ string) (int, error) {
	return 0, ErrBrokerOutOfProcess
}

// ─── key helpers ─────────────────────────────────────────────────────────────

// extractProviderFromKey extracts the provider component from a cache key.
// Cache keys are null-byte-separated: provider\x00capability\x00actor\x00sessionID\x00namespace
func extractProviderFromKey(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '\x00' {
			return key[:i]
		}
	}
	return key
}

// extractActorFromKey extracts the actor component from a cache key.
// Key structure: provider\x00capability\x00actor\x00sessionID\x00namespace
func extractActorFromKey(key string) string {
	parts := splitKey(key)
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// splitKey splits a cache key on null bytes.
func splitKey(key string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '\x00' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	parts = append(parts, key[start:])
	return parts
}

// deriveScopedTokenID produces a stable, opaque identifier for a cache entry.
// It is HMAC'd from the raw cache key using the broker's per-instance hmacKey
// so raw provider/actor values are not exposed.
// The identifier is used as the "token ID" in revoke operations.
func deriveScopedTokenID(hmacKey []byte, key string) string {
	return hashID(hmacKey, key)[:12]
}
