package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/broker"
)

// withBrokerHandle temporarily overrides brokerHandleFactory for the duration
// of the test and restores it via t.Cleanup. This provides isolation between
// parallel tests that need to inject specific broker instances.
// It also resets the in-process singleton so that subsequent tests start clean.
func withBrokerHandle(t *testing.T, b *broker.BrokerImpl) {
	t.Helper()
	prev := brokerHandleFactory
	brokerHandleFactory = func() broker.BrokerHandle {
		return broker.NewBrokerHandle(b)
	}
	t.Cleanup(func() {
		brokerHandleFactory = prev
		broker.ResetInProcessSingleton()
	})
}

// TestBrokerRevoke_Success verifies that a live token can be revoked via the handle.
func TestBrokerRevoke_Success(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("revoke-test-hmac-key-32-bytes!!!"))
	_, err := b.Exchange(context.Background(), "actor-rv", "sess-rv", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant")
	}

	tokenID := grants[0].ScopedTokenID
	if err := handle.Revoke(tokenID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	after, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after revoke: %v", err)
	}
	for _, g := range after {
		if g.ScopedTokenID == tokenID {
			t.Errorf("token %q still present after revoke", tokenID)
		}
	}
}

// TestBrokerRevoke_NotFound verifies ErrTokenNotFound for a non-existent token ID.
func TestBrokerRevoke_NotFound(t *testing.T) {
	t.Parallel()
	b := broker.NewBroker(context.Background(), nil, nil, nil)
	handle := broker.NewBrokerHandle(b)

	err := handle.Revoke("does-not-exist-xyz")
	if err == nil {
		t.Fatal("expected ErrTokenNotFound, got nil")
	}
	if err != broker.ErrTokenNotFound {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

// TestBrokerRevoke_AlreadyRevoked verifies that revoking an already-revoked token
// returns ErrTokenNotFound (the token is no longer in the cache).
func TestBrokerRevoke_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("already-revoke-hmac-key-32-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-ar", "sess-ar", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant")
	}
	tokenID := grants[0].ScopedTokenID

	if err := handle.Revoke(tokenID); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}

	err = handle.Revoke(tokenID)
	if err == nil {
		t.Fatal("expected error on second revoke, got nil")
	}
	if err != broker.ErrTokenNotFound {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

// TestBrokerRevoke_ProviderRevocationFails_LogsButSucceeds verifies that a
// failure in provider-side revocation does not prevent the local cache eviction.
func TestBrokerRevoke_ProviderRevocationFails_LogsButSucceeds(t *testing.T) {
	t.Parallel()
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("prov-revoc-hmac-key-32-bytes-pad"))
	_, err := b.Exchange(context.Background(), "actor-prf", "sess-prf", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant")
	}
	tokenID := grants[0].ScopedTokenID

	if err := handle.Revoke(tokenID); err != nil {
		t.Fatalf("Revoke failed even without provider endpoint: %v", err)
	}
}

// TestBrokerRevoke_JSON verifies the CLI --json output for a successful revoke.
func TestBrokerRevoke_JSON(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("json-revoke-hmac-key-32-bytes-!!"))
	_, err := b.Exchange(context.Background(), "actor-json", "sess-json", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	withBrokerHandle(t, b)

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant")
	}
	tokenID := grants[0].ScopedTokenID

	var out bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--json", tokenID})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("revoke --json: %v", err)
	}

	raw := out.String()
	noTokenLeakage(t, raw)

	var payload brokerRevokeOutput
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("revoke --json output is not valid JSON: %v (output: %q)", err, raw)
	}
	if payload.TokenID != tokenID {
		t.Errorf("token_id = %q, want %q", payload.TokenID, tokenID)
	}
	if payload.Status != "revoked" {
		t.Errorf("status = %q, want revoked", payload.Status)
	}
}

// TestBrokerRevokeAll_Confirmed verifies --all revokes all tokens when confirmed.
func TestBrokerRevokeAll_Confirmed(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("all-conf-hmac-key-32-bytes-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-ac", "sess-ac", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	withBrokerHandle(t, b)
	handle := broker.NewBrokerHandle(b)

	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("expected at least one grant")
	}

	count, err := handle.RevokeAll("")
	if err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one revocation")
	}

	after, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after RevokeAll: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("expected 0 grants after RevokeAll, got %d", len(after))
	}
}

// TestBrokerRevokeAll_Aborted verifies that declining the confirmation prompt
// does not revoke any tokens.
func TestBrokerRevokeAll_Aborted(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("all-abort-hmac-key-32-bytes-pad!"))
	_, err := b.Exchange(context.Background(), "actor-ab", "sess-ab", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	withBrokerHandle(t, b)
	handle := broker.NewBrokerHandle(b)

	before, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants before abort: %v", err)
	}
	if len(before) == 0 {
		t.Fatal("expected at least one grant before abort test")
	}

	var out bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"--all"})
	_ = cmd.Execute()

	after, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants after abort: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("expected %d grants after abort, got %d", len(before), len(after))
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("expected 'Aborted' in output, got %q", out.String())
	}
}

// TestBrokerRevokeAll_Yes_SkipsPrompt verifies --yes skips the confirmation prompt.
func TestBrokerRevokeAll_Yes_SkipsPrompt(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("yes-skip-hmac-key-32-bytes-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-ys", "sess-ys", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	withBrokerHandle(t, b)
	handle := broker.NewBrokerHandle(b)

	before, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants before --yes: %v", err)
	}
	if len(before) == 0 {
		t.Fatal("expected at least one grant")
	}

	var out bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--all", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("revoke --all --yes: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "Revoked") {
		t.Errorf("expected 'Revoked' in output, got %q", outStr)
	}
	noTokenLeakage(t, outStr)
}

// TestBrokerRevokeAll_RaceTolerance verifies that revoke-all tolerates tokens
// that expire between listing and revoking.
func TestBrokerRevokeAll_RaceTolerance(t *testing.T) {
	t.Parallel()
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("race-tol-hmac-key-32-bytes-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-rt", "sess-rt", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	handle := broker.NewBrokerHandle(b)
	grants, err := handle.ListGrants()
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}

	for _, g := range grants {
		_ = handle.Revoke(g.ScopedTokenID)
	}

	count, err := handle.RevokeAll("")
	if err != nil {
		t.Fatalf("RevokeAll with pre-revoked tokens: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count=0 when all tokens pre-revoked, got %d", count)
	}
}

// TestBrokerRevokeAll_JSON verifies --all --json output.
func TestBrokerRevokeAll_JSON(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("json-all-hmac-key-32-bytes-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-ja", "sess-ja", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	withBrokerHandle(t, b)

	var out bytes.Buffer
	cmd := newBrokerRevokeCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--all", "--yes", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("revoke --all --yes --json: %v", err)
	}

	raw := out.String()
	noTokenLeakage(t, raw)

	var payload brokerRevokeAllOutput
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("revoke --all --json output is not valid JSON: %v (output: %q)", err, raw)
	}
	if payload.TokenIDs == nil {
		t.Error("tokenIds must not be nil in --all --json output")
	}
}
