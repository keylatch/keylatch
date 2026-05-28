package broker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker"
)

// canaryToken is a known-format token that must never appear in observable outputs.
const canaryToken = "sk-canary-PHASE13-0xDEADBEEF"

// mockCanaryStrategy implements ExchangeStrategy returning the canary token.
type mockCanaryStrategy struct {
	provider string
}

func (m *mockCanaryStrategy) Provider() string { return m.provider }
func (m *mockCanaryStrategy) Exchange(_ context.Context, _, _, _ string) (broker.ExchangeResult, error) {
	// Return canaryToken as tokenBytes — it must never appear in metadata.
	return broker.NewExchangeResult(m.provider, "cap", time.Hour, broker.FreshExchange, []byte(canaryToken)), nil
}

// captureEmitter captures all emitted audit events.
type captureEmitter struct {
	events []audit.Event
}

func (e *captureEmitter) Emit(_ context.Context, ev audit.Event) error {
	e.events = append(e.events, ev)
	return nil
}

// assertNoCanary fails the test if canaryToken appears anywhere in s.
func assertNoCanary(t *testing.T, label, s string) {
	t.Helper()
	if strings.Contains(s, canaryToken) {
		t.Errorf("canary token found in %s output", label)
	}
}

// TestCanaryAbsentFromExchangeResult verifies the canary token is absent from
// all ExchangeResult metadata fields (provider, capability, ExchangeType).
func TestCanaryAbsentFromExchangeResult(t *testing.T) {
	emitter := &captureEmitter{}
	strategies := map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}
	b := broker.NewBroker(context.Background(), strategies, emitter, []byte("test-hmac-key-32-bytes-pad!!!!!!"))

	result, err := b.Exchange(context.Background(), "actor", "sess", "canary-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Check metadata fields.
	assertNoCanary(t, "result.Provider", result.Provider)
	assertNoCanary(t, "result.Capability", result.Capability)
	assertNoCanary(t, "result.ExchangeType", string(result.ExchangeType))
}

// TestCanaryAbsentFromAuditEvent verifies the canary token is absent from all audit events.
func TestCanaryAbsentFromAuditEvent(t *testing.T) {
	emitter := &captureEmitter{}
	strategies := map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}
	b := broker.NewBroker(context.Background(), strategies, emitter, []byte("test-hmac-key-32-bytes-pad!!!!!!"))

	_, err := b.Exchange(context.Background(), "actor", "sess", "canary-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	for i, ev := range emitter.events {
		evJSON, _ := json.Marshal(ev)
		assertNoCanary(t, "audit_event["+string(rune('0'+i))+"]", string(evJSON))
	}
}

// TestCanaryAbsentFromCacheHitResult verifies the canary token is absent after a cache hit.
func TestCanaryAbsentFromCacheHitResult(t *testing.T) {
	emitter := &captureEmitter{}
	strategies := map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}
	b := broker.NewBroker(context.Background(), strategies, emitter, []byte("test-hmac-key-32-bytes-pad!!!!!!"))

	ctx := context.Background()
	// First exchange — populates cache.
	_, _ = b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	emitter.events = nil

	// Second exchange — cache hit.
	result, err := b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("cache-hit exchange: %v", err)
	}

	assertNoCanary(t, "cache_hit.Provider", result.Provider)
	assertNoCanary(t, "cache_hit.Capability", result.Capability)

	for i, ev := range emitter.events {
		evJSON, _ := json.Marshal(ev)
		s := "cache_hit_audit_event[" + itoa(i) + "]"
		assertNoCanary(t, s, string(evJSON))
	}
}

// TestCanaryAbsentFromRevokeReceipt verifies no canary token in revoke audit events.
func TestCanaryAbsentFromRevokeReceipt(t *testing.T) {
	emitter := &captureEmitter{}
	strategies := map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}
	b := broker.NewBroker(context.Background(), strategies, emitter, []byte("test-hmac-key-32-bytes-pad!!!!!!"))

	ctx := context.Background()
	_, _ = b.Exchange(ctx, "actor", "sess-revoke", "canary-provider", "cap", "ns")

	// Clear events from exchange; only capture revoke events.
	emitter.events = nil

	err := b.Revoke(ctx, "sess-revoke")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Assert: no canary token in any revoke-phase audit event.
	for _, ev := range emitter.events {
		evStr := fmt.Sprintf("%v", ev)
		if strings.Contains(evStr, canaryToken) {
			t.Errorf("canary token found in revoke audit event: %v", ev)
		}
	}
}

// TestCanaryAbsentFromAllStrategies runs the canary check for all 8 strategy names.
func TestCanaryAbsentFromAllStrategies(t *testing.T) {
	strategies := []string{
		"oauth_refresh", "aws_sts", "github_app",
		"google_oauth", "microsoft_oauth", "dropbox_oauth",
		"static_gateway", "slack_token",
	}

	for _, stratName := range strategies {
		stratName := stratName
		t.Run(stratName, func(t *testing.T) {
			emitter := &captureEmitter{}
			strats := map[string]broker.ExchangeStrategy{
				stratName: &mockCanaryStrategy{provider: stratName},
			}
			b := broker.NewBroker(context.Background(), strats, emitter, []byte("test-hmac-key-32-bytes-pad!!!!!!"))

			result, err := b.Exchange(context.Background(), "actor", "sess", stratName, "cap", "ns")
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}

			// Check result metadata.
			metaJSON, _ := json.Marshal(result)
			if bytes.Contains(metaJSON, []byte(canaryToken)) {
				t.Errorf("canary token found in result metadata for strategy %s", stratName)
			}

			// Check audit events.
			for _, ev := range emitter.events {
				evJSON, _ := json.Marshal(ev)
				if bytes.Contains(evJSON, []byte(canaryToken)) {
					t.Errorf("canary token found in audit event for strategy %s", stratName)
				}
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
