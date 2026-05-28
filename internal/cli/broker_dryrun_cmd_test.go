package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/broker"
)

// newTestBrokerForDryRun creates an isolated BrokerImpl for dry-run CLI tests.
func newTestBrokerForDryRun(t *testing.T) *broker.BrokerImpl {
	t.Helper()
	return broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("dryrun-test-hmac-key-32-bytes-!!"))
}

// TestBrokerDryRun_OutOfProcess verifies dry-run CLI returns no credential leakage
// regardless of in/out-of-process state.
func TestBrokerDryRun_OutOfProcess(t *testing.T) {
	t.Parallel()
	var errBuf bytes.Buffer
	cmd := newBrokerDryRunCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&errBuf)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"openrouter", "node script.js"})
	_ = cmd.Execute()
	noTokenLeakage(t, errBuf.String())
}

// TestBrokerDryRun_Allow verifies that dry-run returns allow for a known provider.
func TestBrokerDryRun_Allow(t *testing.T) {
	t.Parallel()
	b := newTestBrokerForDryRun(t)
	handle := broker.NewBrokerHandle(b)

	result, err := handle.DryRunExchange("openrouter", "node main.js")
	if err != nil {
		t.Fatalf("DryRunExchange: %v", err)
	}
	if result.PolicyDecision != "allow" {
		t.Errorf("PolicyDecision = %q, want allow", result.PolicyDecision)
	}
	if len(result.ScopesRequested) == 0 {
		t.Error("ScopesRequested must not be empty")
	}
	if result.ScopedTokenTTL <= 0 {
		t.Error("ScopedTokenTTL must be positive")
	}
}

// TestBrokerDryRun_Deny is reserved for when the policy engine is wired up.
// Currently the broker always returns "allow"; this test documents the
// expected future behaviour.
func TestBrokerDryRun_Deny(t *testing.T) {
	t.Parallel()
	// TODO(epic-24): wire policy engine so that deny is tested here.
	b := newTestBrokerForDryRun(t)
	handle := broker.NewBrokerHandle(b)

	result, err := handle.DryRunExchange("openrouter", "curl https://evil.example.com")
	if err != nil {
		t.Fatalf("DryRunExchange: %v", err)
	}
	if result.PolicyDecision == "" {
		t.Error("PolicyDecision must not be empty")
	}
	if result.Reason == "" {
		t.Error("Reason must not be empty")
	}
}

// TestBrokerDryRun_UnsupportedProvider verifies that dry-run returns an actionable
// error for a provider with no broker configuration.
func TestBrokerDryRun_UnsupportedProvider(t *testing.T) {
	t.Parallel()
	b := newTestBrokerForDryRun(t)
	handle := broker.NewBrokerHandle(b)

	_, err := handle.DryRunExchange("no-such-provider", "node")
	if err == nil {
		t.Fatal("expected error for unsupported provider, got nil")
	}
	if !strings.Contains(err.Error(), "no broker configuration") &&
		err != broker.ErrProviderNoBrokerConfig {
		t.Errorf("expected ErrProviderNoBrokerConfig, got %v", err)
	}
}

// TestBrokerDryRun_NoCacheMutation verifies that DryRunExchange never mutates
// the broker cache.
func TestBrokerDryRun_NoCacheMutation(t *testing.T) {
	t.Parallel()
	b := newTestBrokerForDryRun(t)
	handle := broker.NewBrokerHandle(b)

	before, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants before: %v", err)
	}

	_, err = handle.DryRunExchange("openrouter", "node")
	if err != nil {
		t.Fatalf("DryRunExchange: %v", err)
	}

	after, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after: %v", err)
	}

	if len(after) != len(before) {
		t.Errorf("DryRunExchange mutated cache: before=%d after=%d grants", len(before), len(after))
	}
}

// TestBrokerDryRun_JSON verifies that the dry-run CLI command emits valid JSON
// with the --json flag.
func TestBrokerDryRun_JSON(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := newTestBrokerForDryRun(t)
	withBrokerHandle(t, b)

	var out bytes.Buffer
	cmd := newBrokerDryRunCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--json", "openrouter", "node"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("dry-run --json: %v", err)
	}

	raw := out.String()
	noTokenLeakage(t, raw)

	var payload brokerDryRunOutput
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Errorf("dry-run --json output is not valid JSON: %v (output: %q)", err, raw)
	}
	if payload.Provider != "openrouter" {
		t.Errorf("provider = %q, want openrouter", payload.Provider)
	}
	if strings.Contains(raw, "sk-") {
		t.Error("dry-run JSON must not contain sk- prefix tokens")
	}
}
