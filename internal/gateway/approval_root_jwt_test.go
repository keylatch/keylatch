package gateway_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// approvalRootTestServer starts a gateway server with a given signing key.
func approvalRootTestServer(t *testing.T, key []byte, storePath string) (port int, cancel func()) {
	t.Helper()
	port = freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   filepath.Dir(storePath) + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, ctxCancel := context.WithCancel(context.Background())
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)
	return port, ctxCancel
}

// doApprovalRootRequest fires a POST to a sandboxed route.
func doApprovalRootRequest(t *testing.T, port int, jwtStr, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d%s", port, path),
		strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

// readBody reads and closes response body; returns status + error json field.
func readBody(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	code := ""
	// minimal parse: find "error":"..."
	body := string(b)
	if idx := strings.Index(body, `"error":"`); idx >= 0 {
		rest := body[idx+9:]
		if end := strings.Index(rest, `"`); end >= 0 {
			code = rest[:end]
		}
	}
	return resp.StatusCode, code
}

// TestGateway_TwoPerson_LLMSession_Missing_403 verifies that llm_session=true +
// two_person=false + ApprovalRootHMAC set → 403 llm_session_requires_two_person_approval.
func TestGateway_TwoPerson_LLMSession_Missing_403(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint a token: LLMSession=true, ApprovalRootHMAC present, TwoPerson=false.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:          "llm-actor",
		Capabilities:   []string{"sentry.error_reporting"},
		TTL:            1 * time.Hour,
		LLMSession:     true,
		ApprovalRootID: "some-root-id", // triggers ApprovalRootHMAC in token
		TwoPerson:      false,
		SigningKey:     key,
		StorePath:      storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := approvalRootTestServer(t, key, storePath)
	defer cancel()

	resp := doApprovalRootRequest(t, port, jwtStr, "/api/sentry/error_reporting")
	status, errCode := readBody(t, resp)
	if status != http.StatusForbidden {
		t.Errorf("expected 403, got %d (error=%s)", status, errCode)
		return
	}
	if errCode != "llm_session_requires_two_person_approval" {
		t.Errorf("expected llm_session_requires_two_person_approval, got %q", errCode)
	}
}

// TestGateway_TwoPerson_LLMSession_Present_Allowed verifies that llm_session=true +
// two_person=true + ApprovalRootHMAC set → passes the two-person gate (exception).
func TestGateway_TwoPerson_LLMSession_Present_Allowed(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint with TwoPerson=true.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:           "llm-actor",
		Capabilities:    []string{"sentry.error_reporting"},
		TTL:             1 * time.Hour,
		LLMSession:      true,
		ApprovalRootID:  "root-a",
		ApprovalRootIDs: []string{"root-a", "root-b"},
		TwoPerson:       true,
		SigningKey:      key,
		StorePath:       storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := approvalRootTestServer(t, key, storePath)
	defer cancel()

	resp := doApprovalRootRequest(t, port, jwtStr, "/api/sentry/error_reporting")
	// The request will proceed past the two-person gate and reach broker.Exchange,
	// which returns ErrExchangeUnsupported in the test environment → 503.
	// Any status other than 403 (two_person_approval) means the gate passed.
	status, errCode := readBody(t, resp)
	if status == http.StatusForbidden && errCode == "llm_session_requires_two_person_approval" {
		t.Errorf("expected two-person gate to pass, but got 403 two_person_approval_required")
	}
}

// TestGateway_LLMSession_NoApprovalRoot_NormalFlow verifies that llm_session=true
// without an ApprovalRootHMAC does NOT trigger the two-person gate (normal flow).
func TestGateway_LLMSession_NoApprovalRoot_NormalFlow(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// No ApprovalRootID — plain LLM session token.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "llm-actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		LLMSession:   true,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := approvalRootTestServer(t, key, storePath)
	defer cancel()

	resp := doApprovalRootRequest(t, port, jwtStr, "/api/sentry/error_reporting")
	status, errCode := readBody(t, resp)
	// Must NOT be blocked by two-person gate.
	if status == http.StatusForbidden && errCode == "llm_session_requires_two_person_approval" {
		t.Errorf("plain LLM session should not be blocked by two-person gate")
	}
}
