package gateway

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy"
)

// TestGatewayNew_RejectsPermissivePolicy is the layer-(a) regression test
// for the 2026-08-06 blocking review finding: a gateway-loaded policy file
// with mode=permissive must fail server startup, not load successfully and
// panic on the first LLM-session request (policy.Check panics whenever
// req.LLMSession && Mode==ModePermissive — the gateway can always receive
// LLMSession=true requests, so permissive mode is never safe here).
func TestGatewayNew_RejectsPermissivePolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModePermissive,
	}); err != nil {
		t.Fatalf("policy.Save: %v", err)
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	_, err := New(ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: filepath.Join(dir, "tokens.json"),
		Env:            llmcontext.DefaultLookup,
		PolicyPath:     policyPath,
	})
	if err == nil {
		t.Fatal("expected New to reject a permissive-mode policy, got nil error")
	}
	if !strings.Contains(err.Error(), "permissive") {
		t.Errorf("error should name the permissive-mode problem, got %q", err.Error())
	}
}

// TestGatewayNew_EnforcingPolicy_StillLoads is a control case proving the
// permissive-mode rejection above doesn't accidentally reject every policy
// — enforcing mode (the only mode valid for the gateway) still loads fine.
func TestGatewayNew_EnforcingPolicy_StillLoads(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
	}); err != nil {
		t.Fatalf("policy.Save: %v", err)
	}

	key := make([]byte, 32)
	_, _ = rand.Read(key)

	srv, err := New(ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: filepath.Join(dir, "tokens.json"),
		Env:            llmcontext.DefaultLookup,
		PolicyPath:     policyPath,
	})
	if err != nil {
		t.Fatalf("New: unexpected error for enforcing-mode policy: %v", err)
	}
	if srv.policy == nil {
		t.Fatal("expected srv.policy to be loaded")
	}
}

// TestGatewayHandler_PolicyPanicRecovered is the layer-(b) regression test:
// a defensive belt-and-braces check that Step 6 converts any panic out of
// policy.Check into a proper 403 JSON response plus an audit event, instead
// of an unguarded panic (which, over a real net/http.Server, surfaces to
// the client as a bare connection reset/EOF with no audit trail).
//
// gateway.New's load-time guard (tested above) should make the invariant
// violation unreachable via the normal load path, so this test forces the
// state directly — simulating any future policy path (e.g. a hypothetical
// in-place reload) that doesn't go through New()'s validation — to prove
// the Step 6 recover() itself holds independently of the load-time guard.
func TestGatewayHandler_PolicyPanicRecovered(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	storePath := filepath.Join(dir, "tokens.json")

	// Real audit logger so we can assert an event was actually recorded on
	// the panic-recovered deny path — the exact gap the review flagged
	// (an unguarded panic never reaches s.logAudit).
	auditDir := filepath.Join(dir, "auditlogs")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir auditlogs: %v", err)
	}
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	for i := range dek {
		dek[i] = byte(i + 100)
	}
	auditLogger, err := audit.Open(filepath.Join(auditDir, "audit.log"), salt, dek)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer auditLogger.Close() //nolint:errcheck

	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Mode:          policy.ModeEnforcing,
	}); err != nil {
		t.Fatalf("policy.Save: %v", err)
	}

	srv, err := New(ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		PolicyPath:     policyPath,
		AuditLogger:    auditLogger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Force the invariant-violating state New()'s load-time guard rejects,
	// to test the independent Step 6 recover() layer.
	srv.policy.Mode = policy.ModePermissive

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

	req := httptest.NewRequest(http.MethodPost, "/api/openrouter/chat.completion", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// httptest.ResponseRecorder does NOT recover panics on its own — if
	// checkPolicySafe's recover() did not catch the invariant panic, this
	// call panics and fails the test loudly, proving the fix rather than
	// silently passing.
	srv.gatewayHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from the panic-recovered deny, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("expected a JSON error body (not a bare connection reset), got %q: %v", rr.Body.String(), err)
	}
	if errResp.Error != "policy_denied" {
		t.Errorf("expected error=policy_denied, got %q", errResp.Error)
	}

	events, err := auditLogger.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("audit Scan: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == audit.ActionPolicyCheck && e.Outcome == audit.OutcomeDenied {
			found = true
		}
	}
	if !found {
		t.Error("expected a policy_check/denied audit event for the panic-recovered deny, found none")
	}
}
