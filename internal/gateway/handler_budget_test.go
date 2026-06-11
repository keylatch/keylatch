package gateway_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/budget"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// budgetTestServer starts a gateway with a per-actor budget of limit requests
// per hour and returns the port and a shutdown func.
func budgetTestServer(t *testing.T, key []byte, storePath string, limit float64) (port int, cancel context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	counter := budget.NewInMemoryBudgetCounter(ctx, budget.BudgetPolicy{
		SpendPerHour: limit,
	})
	port = freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Dir(storePath) + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Budget:         counter,
	})
	if err != nil {
		cancel()
		t.Fatalf("New: %v", err)
	}
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	return port, cancel
}

// TestHandler_Budget_DeniesOverLimit verifies that requests beyond the
// configured per-actor budget are rejected with 429 and a value-free denial
// receipt, while requests within budget pass the gate.
func TestHandler_Budget_DeniesOverLimit(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "budget-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := budgetTestServer(t, key, storePath, 2)
	defer cancel()

	// First two requests must pass the budget gate (they may fail later in
	// the chain — vault/exchange — but never with 429).
	for i := 0; i < 2; i++ {
		resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 within budget", i+1)
		}
	}

	// Third request exceeds the 2/hour budget.
	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 over budget, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var receipt budget.BudgetDenialReceipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatalf("denial receipt must be valid JSON: %v (body: %s)", err, body)
	}
	if receipt.ActorHMAC == "" {
		t.Error("denial receipt must carry an HMAC'd actor ID")
	}
	if receipt.ActorHMAC == "budget-actor" {
		t.Error("denial receipt must not leak the raw actor ID")
	}
	if receipt.Capability != "openrouter.chat.completion" {
		t.Errorf("receipt capability = %q", receipt.Capability)
	}
	if receipt.LimitType != "request_budget" {
		t.Errorf("receipt limit_type = %q", receipt.LimitType)
	}
}

// TestHandler_Budget_NilCounterPassesThrough verifies that a gateway without
// a configured budget applies no enforcement.
func TestHandler_Budget_NilCounterPassesThrough(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "unbudgeted-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	for i := 0; i < 5; i++ {
		resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d: 429 from a gateway with no budget configured", i+1)
		}
	}
}
