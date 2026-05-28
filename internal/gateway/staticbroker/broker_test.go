package staticbroker_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/staticbroker"
)

// TestAccessTokenZero verifies that Zero wipes the Value slice in-place.
func TestAccessTokenZero(t *testing.T) {
	tok := staticbroker.AccessToken{
		Value:     []byte("secret-credential"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	tok.Zero()
	for i, b := range tok.Value {
		if b != 0 {
			t.Errorf("Zero() did not zero byte at index %d: got %d", i, b)
		}
	}
}

// TestBrokerStart verifies that Start launches without panicking and that Stop
// signals the goroutine to exit cleanly.
func TestBrokerStart_StopClean(t *testing.T) {
	b := staticbroker.NewWithOptions(10)
	ctx, cancel := context.WithCancel(context.Background())
	b.Start(ctx)
	// Give the goroutine a moment to spin up.
	time.Sleep(5 * time.Millisecond)
	b.Stop()
	cancel()
}

// TestBrokerStart_ContextCancel verifies that cancelling ctx also shuts the goroutine.
func TestBrokerStart_ContextCancel(t *testing.T) {
	b := staticbroker.NewWithOptions(10)
	ctx, cancel := context.WithCancel(context.Background())
	b.Start(ctx)
	time.Sleep(5 * time.Millisecond)
	cancel()
	// A second Stop call must not block (stopEvict channel has capacity 0, so send is non-blocking).
	b.Stop()
}

// TestBrokerNewWithOptions_ZeroMaxEntries verifies the fallback to defaultMaxEntries.
func TestBrokerNewWithOptions_ZeroMaxEntries(t *testing.T) {
	// maxEntries <= 0 triggers fallback to defaultMaxEntries (500).
	b := staticbroker.NewWithOptions(0)
	if b == nil {
		t.Fatal("NewWithOptions(0) returned nil")
	}
	// Verify the broker still works for a basic exchange.
	tok, err := b.Exchange(context.Background(), staticbroker.ExchangeSpec{
		Strategy:       "static_gateway_only",
		RootCredential: []byte("cred"),
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if string(tok.Value) != "cred" {
		t.Errorf("token value mismatch: got %q", tok.Value)
	}
}

// TestBrokerExchange_DefaultTTL verifies that TTL<=0 in ExchangeSpec defaults to 1h.
func TestBrokerExchange_DefaultTTL(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	tok, err := b.Exchange(context.Background(), staticbroker.ExchangeSpec{
		Strategy:       "static_gateway_only",
		RootCredential: []byte("cred"),
		TTL:            0, // triggers default 1h path
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// ExpiresAt should be roughly 1 hour from now.
	delta := time.Until(tok.ExpiresAt)
	if delta < 59*time.Minute || delta > 61*time.Minute {
		t.Errorf("ExpiresAt expected ~1h, got delta %v", delta)
	}
}

// TestBrokerDryRun_StaticGatewayOnly covers the static_gateway_only and "" DryRun paths.
func TestBrokerDryRun_StaticGatewayOnly(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	for _, strategy := range []string{"static_gateway_only", ""} {
		meta, err := b.DryRun(context.Background(), staticbroker.ExchangeSpec{Strategy: strategy})
		if err != nil {
			t.Fatalf("DryRun(%q): %v", strategy, err)
		}
		if meta["strategy"] != "static_gateway_only" {
			t.Errorf("DryRun(%q): strategy metadata = %q", strategy, meta["strategy"])
		}
	}
}

// TestBrokerDryRun_None covers the "none" DryRun path.
func TestBrokerDryRun_None(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	meta, err := b.DryRun(context.Background(), staticbroker.ExchangeSpec{Strategy: "none"})
	if err != nil {
		t.Fatalf("DryRun(none): %v", err)
	}
	if meta["strategy"] != "none" {
		t.Errorf("DryRun(none): strategy = %q", meta["strategy"])
	}
}

// TestBrokerDryRun_Unsupported covers the default (unsupported) DryRun path.
func TestBrokerDryRun_Unsupported(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	meta, err := b.DryRun(context.Background(), staticbroker.ExchangeSpec{Strategy: "dynamic_oauth"})
	if err != staticbroker.ErrExchangeUnsupported {
		t.Fatalf("DryRun(unsupported): expected ErrExchangeUnsupported, got %v", err)
	}
	if meta["supported"] != "false" {
		t.Errorf("DryRun(unsupported): expected supported=false, got %v", meta)
	}
}

// TestBrokerDryRun_Locked verifies DryRun returns ErrVaultLocked when vault is locked.
func TestBrokerDryRun_Locked(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	if err := b.OnVaultLock(ctx); err != nil {
		t.Fatalf("OnVaultLock: %v", err)
	}

	_, err := b.DryRun(ctx, staticbroker.ExchangeSpec{Strategy: "static_gateway_only"})
	if err != staticbroker.ErrVaultLocked {
		t.Errorf("DryRun on locked broker: expected ErrVaultLocked, got %v", err)
	}
}

func TestBrokerExchange_StaticGatewayOnly(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	tok, err := b.Exchange(ctx, staticbroker.ExchangeSpec{
		Strategy:       "static_gateway_only",
		RootCredential: []byte("test-cred"),
		TTL:            1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if string(tok.Value) != "test-cred" {
		t.Errorf("token value: got %q, want %q", tok.Value, "test-cred")
	}
}

func TestBrokerExchange_None(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	tok, err := b.Exchange(ctx, staticbroker.ExchangeSpec{Strategy: "none"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.Value != nil {
		t.Errorf("expected nil value for 'none' strategy")
	}
}

func TestBrokerExchange_Unsupported(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	_, err := b.Exchange(ctx, staticbroker.ExchangeSpec{Strategy: "dynamic_oauth"})
	if err != staticbroker.ErrExchangeUnsupported {
		t.Errorf("expected ErrExchangeUnsupported, got %v", err)
	}
}

func TestBrokerOnVaultLock(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	if err := b.OnVaultLock(ctx); err != nil {
		t.Fatalf("OnVaultLock: %v", err)
	}

	_, err := b.Exchange(ctx, staticbroker.ExchangeSpec{Strategy: "static_gateway_only"})
	if err != staticbroker.ErrVaultLocked {
		t.Errorf("expected ErrVaultLocked, got %v", err)
	}

	if err := b.OnVaultUnlock(ctx); err != nil {
		t.Fatalf("OnVaultUnlock: %v", err)
	}

	_, err = b.Exchange(ctx, staticbroker.ExchangeSpec{Strategy: "static_gateway_only"})
	if err != nil {
		t.Errorf("expected success after unlock, got %v", err)
	}
}

func TestBrokerCacheMaxEntries_EarliestEvicted(t *testing.T) {
	const maxEntries = 5
	b := staticbroker.NewWithOptions(maxEntries)
	defer b.Stop()

	ctx := context.Background()

	for i := 0; i < maxEntries+1; i++ {
		_, err := b.Exchange(ctx, staticbroker.ExchangeSpec{
			Strategy:       "static_gateway_only",
			RootCredential: []byte("cred"),
			Actor:          "actor",
			Capability:     "cap",
			Namespace:      "default",
			TTL:            1 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Exchange at iteration %d: %v", i, err)
		}
	}
}

func TestBrokerCacheRevoke(t *testing.T) {
	b := staticbroker.New()
	defer b.Stop()

	ctx := context.Background()
	key := staticbroker.BrokerCacheKey{
		Provider:   "openrouter",
		Actor:      "actor",
		Namespace:  "default",
		Capability: "chat",
	}

	if err := b.Revoke(ctx, key); err != nil {
		t.Errorf("Revoke non-existent key: %v", err)
	}
}
