package broker

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

func TestZeroingFreshResultKeepsCachedCredential(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	fresh, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("fresh exchange: %v", err)
	}
	if fresh.ExchangeType != FreshExchange {
		t.Fatalf("exchange type = %v, want fresh", fresh.ExchangeType)
	}
	fresh.Zero()

	hit, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("cached exchange: %v", err)
	}
	if hit.ExchangeType != CacheHit {
		t.Fatalf("exchange type = %v, want cache hit", hit.ExchangeType)
	}
	if got := hit.TokenBytes(); !bytes.Equal(got, []byte("mock-token")) {
		t.Fatalf("cached token = %q after zeroing the fresh result, want %q", got, "mock-token")
	}
}

func TestZeroingCacheHitKeepsCachedCredential(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	for i := range 3 {
		res, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if got := res.TokenBytes(); !bytes.Equal(got, []byte("mock-token")) {
			t.Fatalf("exchange %d token = %q, want %q", i, got, "mock-token")
		}
		res.Zero()
	}
}

func TestRevokeDoesNotZeroReturnedResult(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	if _, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns"); err != nil {
		t.Fatalf("fresh exchange: %v", err)
	}
	hit, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("cached exchange: %v", err)
	}
	if err := b.Revoke(ctx, "sess"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := hit.TokenBytes(); !bytes.Equal(got, []byte("mock-token")) {
		t.Fatalf("result held by caller = %q after revoke, want %q", got, "mock-token")
	}
}

func TestConcurrentCacheHitsAndRevoke(t *testing.T) {
	b := newTestBroker(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				res, err := b.Exchange(ctx, "actor", "sess", "test-provider", "cap", "ns")
				if err == nil {
					if got := res.TokenBytes(); !bytes.Equal(got, []byte("mock-token")) {
						t.Errorf("token = %q, want %q", got, "mock-token")
						return
					}
					res.Zero()
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = b.Revoke(ctx, "sess")
			}
		}()
	}
	wg.Wait()
}

func TestDeriveScopesFromBlankCommand(t *testing.T) {
	for _, command := range []string{"", " ", "\t\n", "   \t "} {
		got := deriveScopesFromCommand("openrouter", command)
		if len(got) != 1 || got[0] != "openrouter.*" {
			t.Fatalf("deriveScopesFromCommand(%q) = %v, want [openrouter.*]", command, got)
		}
	}
}

func TestDryRunWhitespaceCommandDoesNotPanic(t *testing.T) {
	b := newTestBroker(t)
	res, err := dryRunExchange(b, "test-provider", "   ")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(res.ScopesRequested) != 1 || res.ScopesRequested[0] != "test-provider.*" {
		t.Fatalf("scopes = %v, want [test-provider.*]", res.ScopesRequested)
	}
}
