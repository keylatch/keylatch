package broker_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/broker/strategies"
)

// mockOAuthServer returns a test server that simulates an OAuth token endpoint.
func mockOAuthServer(t *testing.T, statusCode int, responseBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, responseBody)
	}))
}

// TestIntegration_OAuthRefreshSuccess tests a successful OAuth exchange.
func TestIntegration_OAuthRefreshSuccess(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	srv := mockOAuthServer(t, 200, `{"access_token":"integration-test-token","expires_in":3600}`)
	defer srv.Close()

	emitter := &captureEmitter{}

	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		srv.URL,
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) {
			return []byte("refresh-token-for-integration"), nil
		},
	)

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, emitter, []byte("integration-test-hmac-key-32!!"))

	result, err := b.Exchange(context.Background(), "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if result.ExchangeType != broker.FreshExchange {
		t.Errorf("expected FreshExchange, got %s", result.ExchangeType)
	}
	if result.TTLRemaining <= 0 {
		t.Error("expected positive TTL")
	}

	// Verify audit event was emitted.
	if len(emitter.events) == 0 {
		t.Fatal("expected audit event to be emitted")
	}
	ev := emitter.events[0]
	if ev.Action != audit.ActionBrokerExchange {
		t.Errorf("expected ActionBrokerExchange, got %s", ev.Action)
	}
}

// TestIntegration_ExpiredRefreshToken tests the invalid_grant error path.
func TestIntegration_ExpiredRefreshToken(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	srv := mockOAuthServer(t, 400, `{"error":"invalid_grant","error_description":"Token expired"}`)
	defer srv.Close()

	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		srv.URL,
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) {
			return []byte("expired-refresh-token"), nil
		},
	)

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, nil, nil)

	_, err := b.Exchange(context.Background(), "actor", "sess", "test-provider", "cap", "ns")
	if err != broker.ErrExpiredRefreshToken {
		t.Errorf("expected ErrExpiredRefreshToken, got %v", err)
	}
}

// TestIntegration_VaultLockDuringExchange verifies ErrVaultLocked is returned.
func TestIntegration_VaultLockDuringExchange(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	srv := mockOAuthServer(t, 200, `{"access_token":"tok","expires_in":3600}`)
	defer srv.Close()

	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		srv.URL,
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) { return []byte("refresh-token"), nil },
	)

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, nil, nil)

	ctx := context.Background()
	b.OnVaultLock(ctx)

	_, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != broker.ErrVaultLocked {
		t.Errorf("expected ErrVaultLocked, got %v", err)
	}
}

// TestIntegration_RevokeFlushesCache verifies that Revoke causes subsequent Exchange to be fresh.
func TestIntegration_RevokeFlushesCache(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + itoa(callCount),
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		srv.URL,
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) { return []byte("refresh-token"), nil },
	)

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, nil, nil)

	ctx := context.Background()

	// First exchange — should be fresh.
	r1, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if r1.ExchangeType != broker.FreshExchange {
		t.Errorf("first: expected FreshExchange, got %s", r1.ExchangeType)
	}

	// Second exchange — should be cache hit.
	r2, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if r2.ExchangeType != broker.CacheHit {
		t.Errorf("second: expected CacheHit, got %s", r2.ExchangeType)
	}

	// Revoke the session.
	if err := b.Revoke(ctx, "sess"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Third exchange — should be fresh again.
	r3, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("third exchange: %v", err)
	}
	if r3.ExchangeType != broker.FreshExchange {
		t.Errorf("third: expected FreshExchange after revoke, got %s", r3.ExchangeType)
	}
}

// TestIntegration_CacheHitAuditEvent verifies ActionBrokerCacheHit is emitted on cache hit.
func TestIntegration_CacheHitAuditEvent(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	srv := mockOAuthServer(t, 200, `{"access_token":"tok","expires_in":3600}`)
	defer srv.Close()

	emitter := &captureEmitter{}
	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		srv.URL,
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) { return []byte("refresh-token"), nil },
	)

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, emitter, []byte("integration-test-hmac-key-32!!"))

	ctx := context.Background()
	_, _ = b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	emitter.events = nil

	_, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("cache-hit exchange: %v", err)
	}

	if len(emitter.events) == 0 {
		t.Fatal("expected cache-hit audit event")
	}
	if emitter.events[0].Action != audit.ActionBrokerCacheHit {
		t.Errorf("expected ActionBrokerCacheHit, got %s", emitter.events[0].Action)
	}
}

// TestIntegration_NetworkFailure verifies error propagation on HTTP failure.
func TestIntegration_NetworkFailure(t *testing.T) {
	t.Cleanup(broker.ResetInProcessSingleton)
	strat := strategies.NewOAuthRefreshStrategy(
		"test-provider",
		"http://127.0.0.1:1", // nothing listening here
		"client-id",
		"client-secret",
		func(actor, namespace string) ([]byte, error) { return []byte("refresh-token"), nil },
	)
	_ = time.After // ensure time is imported

	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"test-provider": strat,
	}, nil, nil)

	_, err := b.Exchange(context.Background(), "actor", "sess", "test-provider", "cap", "ns")
	if err == nil {
		t.Fatal("expected error on network failure, got nil")
	}
}
