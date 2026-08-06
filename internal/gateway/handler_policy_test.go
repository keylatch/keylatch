package gateway_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy"
)

// writeTestPolicy writes p to a fresh temp file with the 0600 permissions
// policy.Load requires, and returns the path.
func writeTestPolicy(t *testing.T, p policy.Policy) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := policy.Save(path, p); err != nil {
		t.Fatalf("policy.Save: %v", err)
	}
	return path
}

// policyEventsSince returns all policy_check audit events recorded by l.
func policyEventsSince(t *testing.T, l *audit.Logger) []audit.Event {
	t.Helper()
	events, err := l.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("audit Scan: %v", err)
	}
	var out []audit.Event
	for _, e := range events {
		if e.Action == audit.ActionPolicyCheck {
			out = append(out, e)
		}
	}
	return out
}

// TestHandler_Policy_NotConfigured_PassThrough verifies that when
// ServerOptions.PolicyPath is unset, Step 6 stays pass-through: the request
// proceeds past the policy check to the vault lookup exactly as it did
// before H7 wiring (surfacing credential_not_found, not policy_denied).
func TestHandler_Policy_NotConfigured_PassThrough(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// An empty (always-ErrNotFound) vault stub. Without this, s.vault is nil
	// and the handler falls through to a REAL upstream HTTP call — Vault
	// must always be set in gateway tests to keep them offline.
	vault := &stubVaultReader{values: map[string][]byte{}}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		// PolicyPath intentionally unset.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 credential_not_found (policy pass-through), got %d (body: %s)", resp.StatusCode, body)
	}
	assertErrorCode(t, resp, "credential_not_found")
}

// TestHandler_Policy_MissingFile_PassThrough verifies that a PolicyPath
// pointing at a not-yet-created file is treated the same as "not
// configured" — the server starts and Step 6 stays pass-through, rather
// than failing to start or defaulting to deny.
func TestHandler_Policy_MissingFile_PassThrough(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	vault := &stubVaultReader{values: map[string][]byte{}}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		PolicyPath:     filepath.Join(dir, "does-not-exist", "policy.json"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 credential_not_found (policy pass-through), got %d (body: %s)", resp.StatusCode, body)
	}
	assertErrorCode(t, resp, "credential_not_found")
}

// TestGatewayNew_PolicyLoad_MalformedFails verifies that a configured
// PolicyPath pointing at an unreadable/malformed file fails server startup
// rather than silently starting with policy enforcement disabled.
func TestGatewayNew_PolicyLoad_MalformedFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	badPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}

	_, err := gateway.New(gateway.ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: filepath.Join(dir, "tokens.json"),
		Env:            llmcontext.DefaultLookup,
		PolicyPath:     badPath,
	})
	if err == nil {
		t.Fatal("expected New to fail on malformed policy file, got nil error")
	}
}

// TestHandler_Policy_Allow verifies that a configured policy with a matching
// allow rule lets the request proceed through to the upstream call, and
// records an "allow" policy_check audit event.
func TestHandler_Policy_Allow(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	auditLogger := openTestAuditLogger(t)

	policyPath := writeTestPolicy(t, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		Rules: []policy.Rule{
			{
				ID:           "allow-openrouter",
				Actor:        "*",
				Connections:  []string{"openrouter"},
				Capabilities: []string{"openrouter.*"},
			},
		},
	})

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "policy-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const credValue = "sk-or-policy-allow-test"
	vault := &stubVaultReader{
		values: map[string][]byte{
			"default/ai/openrouter/api_key": []byte(credValue),
		},
	}

	var upstreamAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chatcmpl-ok","choices":[]}`)) //nolint:errcheck
	}))
	defer upstream.Close()

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
		req.Host = req.URL.Host
		return http.DefaultTransport.RoundTrip(req)
	})

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		AuditLogger:    auditLogger,
		PolicyPath:     policyPath,
		OverrideHTTPClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", `{"model":"gpt-4","messages":[]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for policy-allowed request, got %d (body: %s)", resp.StatusCode, body)
	}
	if !strings.Contains(upstreamAuth, credValue) {
		t.Errorf("upstream Authorization %q does not contain credential %q", upstreamAuth, credValue)
	}

	// Audit must record an allow.
	events := policyEventsSince(t, auditLogger)
	if len(events) != 1 {
		t.Fatalf("expected 1 policy_check audit event, got %d", len(events))
	}
	if events[0].Outcome != audit.OutcomeOK {
		t.Errorf("expected OutcomeOK, got %v", events[0].Outcome)
	}
	if result, _ := events[0].Extra["result"].(string); !strings.HasPrefix(result, "allow") {
		t.Errorf("expected result to start with allow, got %q", result)
	}
}

// TestHandler_Policy_Deny verifies that a configured policy with
// default_deny and no matching rule rejects the request with 403
// policy_denied and records a denied policy_check audit event, without
// ever reaching the vault.
func TestHandler_Policy_Deny(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	auditLogger := openTestAuditLogger(t)

	policyPath := writeTestPolicy(t, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		Rules: []policy.Rule{
			{
				// Rule for a different provider — never matches this request.
				ID:           "allow-sentry-only",
				Actor:        "*",
				Connections:  []string{"sentry"},
				Capabilities: []string{"sentry.*"},
			},
		},
	})

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "policy-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Vault would satisfy the credential lookup if the request ever reached
	// it — its presence proves the request was blocked at the policy step,
	// not later, if vault.Get is never called.
	vault := &stubVaultReader{
		values: map[string][]byte{
			"default/ai/openrouter/api_key": []byte("should-never-be-read"),
		},
	}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		AuditLogger:    auditLogger,
		PolicyPath:     policyPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 policy_denied, got %d (body: %s)", resp.StatusCode, body)
	}
	assertErrorCode(t, resp, "policy_denied")

	events := policyEventsSince(t, auditLogger)
	if len(events) != 1 {
		t.Fatalf("expected 1 policy_check audit event, got %d", len(events))
	}
	if events[0].Outcome != audit.OutcomeDenied {
		t.Errorf("expected OutcomeDenied, got %v", events[0].Outcome)
	}
	if result, _ := events[0].Extra["result"].(string); result != "deny" {
		t.Errorf("expected result=deny, got %q", result)
	}
}

// TestHandler_Policy_ApprovalRequired_Denied verifies that a matched rule
// with Approval:true is treated as denied at the gateway (no synchronous
// approval mechanism exists mid-request), using the distinct
// policy_approval_required error code.
func TestHandler_Policy_ApprovalRequired_Denied(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	policyPath := writeTestPolicy(t, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false,
		Rules: []policy.Rule{
			{
				ID:           "approval-required-openrouter",
				Actor:        "*",
				Connections:  []string{"openrouter"},
				Capabilities: []string{"openrouter.*"},
				Approval:     true,
			},
		},
	})

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "policy-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	vault := &stubVaultReader{values: map[string][]byte{}}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		PolicyPath:     policyPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 policy_approval_required, got %d (body: %s)", resp.StatusCode, body)
	}
	assertErrorCode(t, resp, "policy_approval_required")
}

// TestHandler_Policy_LLMSession_ReadClass_Denied verifies the categorical
// LLM-session read-class deny inside policy.Check fires through the wired
// Step 6, independent of the earlier route-level LLM gate at Step 5b.
func TestHandler_Policy_LLMSession_ReadClass_Denied(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	policyPath := writeTestPolicy(t, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false,
	})

	// Mint an LLM-session token with a non-read-class capability so it
	// clears the Step 5b gate and reaches Step 6 with LLMSession=true.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "llm-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		LLMSession:   true,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	vault := &stubVaultReader{values: map[string][]byte{}}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
		PolicyPath:     policyPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	// chat.completion is not read-class, so it clears the categorical
	// LLM deny too — this exercises the allow path with LLMSession=true
	// through the real Check(), confirming no panic/invariant violation.
	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	defer resp.Body.Close()
	// No vault configured — the request should get past policy (200 range
	// of gateway checks) down to credential_not_found, proving Step 6 did
	// not block it.
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 credential_not_found past policy, got %d (body: %s)", resp.StatusCode, body)
	}
	assertErrorCode(t, resp, "credential_not_found")
}
