package broker_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// newTestBrokerWithStrategies is a helper that creates a BrokerImpl with one
// mock strategy and a HMAC key so ListGrants can hash actor IDs.
// It registers a cleanup to reset the in-process singleton so parallel tests
// do not observe a stale singleton from a prior test.
func newTestBrokerWithStrategies(t *testing.T) *broker.BrokerImpl {
	t.Helper()
	t.Cleanup(broker.ResetInProcessSingleton)
	strat := &mockCanaryStrategy{provider: "test-provider"}
	return broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, nil, []byte("test-hmac-key-32-bytes-pad!!!!!!"))
}

// TestBrokerHandle_InProcess_Smoke verifies that a handle backed by a live
// BrokerImpl returns non-error results.
func TestBrokerHandle_InProcess_Smoke(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)

	// Perform an exchange so there is something in the cache.
	ctx := context.Background()
	_, err := b.Exchange(ctx, "actor-1", "sess-1", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)

	// ListGrants must return the cached entry.
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Error("expected at least one grant after Exchange, got none")
	}

	// Each grant must have non-empty provider and scoped token ID.
	for i, g := range grants {
		if g.Provider == "" {
			t.Errorf("grant[%d].Provider is empty", i)
		}
		if g.ScopedTokenID == "" {
			t.Errorf("grant[%d].ScopedTokenID is empty", i)
		}
		if g.ExpiresAt.IsZero() {
			t.Errorf("grant[%d].ExpiresAt is zero", i)
		}
		if g.ExpiresAt.Before(time.Now()) {
			t.Errorf("grant[%d].ExpiresAt is in the past", i)
		}
	}
}

// TestBrokerHandle_OutOfProcess_Error verifies that an out-of-process handle
// returns ErrBrokerOutOfProcess from every method.
func TestBrokerHandle_OutOfProcess_Error(t *testing.T) {
	t.Parallel()

	// Use NewOutOfProcessHandle to force the out-of-process path regardless of
	// the in-process singleton state (which may be set by other tests).
	handle := broker.NewOutOfProcessHandle()

	t.Run("ListGrants", func(t *testing.T) {
		_, err := handle.ListGrants()
		if err == nil {
			t.Fatal("expected ErrBrokerOutOfProcess, got nil")
		}
		if err != broker.ErrBrokerOutOfProcess {
			t.Errorf("expected ErrBrokerOutOfProcess, got %v", err)
		}
	})

	t.Run("DryRunExchange", func(t *testing.T) {
		_, err := handle.DryRunExchange("openrouter", "node")
		if err == nil {
			t.Fatal("expected ErrBrokerOutOfProcess, got nil")
		}
		if err != broker.ErrBrokerOutOfProcess {
			t.Errorf("expected ErrBrokerOutOfProcess, got %v", err)
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		err := handle.Revoke("tok_abc123")
		if err == nil {
			t.Fatal("expected ErrBrokerOutOfProcess, got nil")
		}
		if err != broker.ErrBrokerOutOfProcess {
			t.Errorf("expected ErrBrokerOutOfProcess, got %v", err)
		}
	})

	t.Run("RevokeAll", func(t *testing.T) {
		_, err := handle.RevokeAll("actor-1")
		if err == nil {
			t.Fatal("expected ErrBrokerOutOfProcess, got nil")
		}
		if err != broker.ErrBrokerOutOfProcess {
			t.Errorf("expected ErrBrokerOutOfProcess, got %v", err)
		}
	})
}

// TestBrokerHandle_ListGrants_NoTokenLeakage verifies that grant metadata never
// contains raw token bytes (canary token must not appear).
func TestBrokerHandle_ListGrants_NoTokenLeakage(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)

	ctx := context.Background()
	_, _ = b.Exchange(ctx, "actor-1", "sess-1", "test-provider", "cap", "ns")

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}

	for i, g := range grants {
		if g.Provider == canaryToken {
			t.Errorf("grant[%d].Provider contains canary token", i)
		}
		if g.ActorHMAC == canaryToken {
			t.Errorf("grant[%d].ActorHMAC contains canary token", i)
		}
		if g.ScopedTokenID == canaryToken {
			t.Errorf("grant[%d].ScopedTokenID contains canary token", i)
		}
	}
}

// TestBrokerHandle_DryRunExchange_InProcess verifies dry-run returns a valid result.
func TestBrokerHandle_DryRunExchange_InProcess(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)
	handle := broker.NewBrokerHandle(b)

	result, err := handle.DryRunExchange("test-provider", "node script.js")
	if err != nil {
		t.Fatalf("DryRunExchange: %v", err)
	}
	if result.Provider != "test-provider" {
		t.Errorf("Provider = %q, want test-provider", result.Provider)
	}
	if result.PolicyDecision == "" {
		t.Error("PolicyDecision is empty")
	}
	if len(result.ScopesRequested) == 0 {
		t.Error("ScopesRequested is empty")
	}
	if result.ScopedTokenTTL <= 0 {
		t.Error("ScopedTokenTTL must be positive")
	}
}

// TestBrokerHandle_DryRunExchange_UnsupportedProvider verifies that a provider
// without a registered strategy returns ErrProviderNoBrokerConfig.
func TestBrokerHandle_DryRunExchange_UnsupportedProvider(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)
	handle := broker.NewBrokerHandle(b)

	_, err := handle.DryRunExchange("no-such-provider", "curl")
	if err == nil {
		t.Fatal("expected error for unsupported provider, got nil")
	}
}

// TestBrokerHandle_Revoke_NotFound verifies that revoking a non-existent token
// returns ErrTokenNotFound.
func TestBrokerHandle_Revoke_NotFound(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)
	handle := broker.NewBrokerHandle(b)

	err := handle.Revoke("does-not-exist")
	if err == nil {
		t.Fatal("expected ErrTokenNotFound, got nil")
	}
	if err != broker.ErrTokenNotFound {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

// TestBrokerHandle_Revoke_Success verifies that a live token can be revoked and
// is no longer listed after revocation.
func TestBrokerHandle_Revoke_Success(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)

	ctx := context.Background()
	_, err := b.Exchange(ctx, "actor-revoke", "sess-revoke", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)

	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant before revoke")
	}

	tokenID := grants[0].ScopedTokenID
	if err := handle.Revoke(tokenID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Token must no longer appear in grants.
	grantsAfter, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after revoke: %v", err)
	}
	for _, g := range grantsAfter {
		if g.ScopedTokenID == tokenID {
			t.Errorf("token %q still appears in grants after revoke", tokenID)
		}
	}
}

// TestBrokerHandle_DryRunExchange_NoCacheMutation verifies that DryRunExchange
// does not add entries to the broker cache.
func TestBrokerHandle_DryRunExchange_NoCacheMutation(t *testing.T) {
	t.Parallel()
	b := newTestBrokerWithStrategies(t)
	handle := broker.NewBrokerHandle(b)

	// Snapshot before.
	before, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants before: %v", err)
	}

	_, err = handle.DryRunExchange("test-provider", "node")
	if err != nil {
		t.Fatalf("DryRunExchange: %v", err)
	}

	// Snapshot after — must be same count.
	after, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("cache mutated by DryRunExchange: before=%d after=%d", len(before), len(after))
	}
}
