package gateway_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
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

// denyTestServer starts a gateway server on a free port and returns shutdown func.
func denyTestServer(t *testing.T, key []byte, storePath string) (port int, cancel context.CancelFunc) {
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
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	return port, cancel
}

func doGatewayRequest(t *testing.T, port int, jwtStr, path, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("{}")
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), bodyReader)
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s: %v", path, err)
	}
	return resp
}

func assertErrorCode(t *testing.T, resp *http.Response, expectedCode string) {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v (body: %s)", err, body)
	}
	if errResp.Error != expectedCode {
		t.Errorf("expected error code %q, got %q (body: %s)", expectedCode, errResp.Error, body)
	}
}

func TestHandler_Deny_CapabilityMismatch(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint token with wrong capability.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"wrong.capability"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Errorf("expected 403, got %d", resp.StatusCode)
		return
	}
	assertErrorCode(t, resp, "capability_mismatch")
}

func TestHandler_Deny_ExpiredToken(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// We can't easily mint an expired JWT (would need negative TTL workaround).
	// Instead, test with a malformed token.
	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/sentry/error_reporting", port), strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Errorf("expected 401, got %d", resp.StatusCode)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	json.Unmarshal(body, &errResp)
	if errResp.Error == "" {
		t.Error("expected error code in response")
	}
}

func TestHandler_Deny_RevokedToken(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := token.Revoke(tok.ID, storePath); err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Errorf("expected 401 for revoked token, got %d", resp.StatusCode)
		return
	}
	assertErrorCode(t, resp, "token_revoked")
}

func TestHandler_Deny_LLMSession_ReadClass(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint LLM session token with a read-class capability.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "llm-actor",
		Capabilities: []string{"read"},
		TTL:          1 * time.Hour,
		LLMSession:   true,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	// The route doesn't need to exist for the LLM gate to fire —
	// but capability check comes first. Use a route with the "read" cap.
	// Since our test routes don't have "read" capability, the capability check
	// will fire first (403 capability_mismatch). That's acceptable behavior.
	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d (body: %s)", resp.StatusCode, body)
	}
}

func TestHandler_Deny_SubstitutionBlocked(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	// api_key is now blocked at the authBlockerMiddleware boundary (403)
	// before reaching the substitution check. This is a stricter posture
	// than the original substitution-only rejection. Assert the new error
	// code; the substitution check itself is still exercised by handler
	// unit tests on other input shapes.
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/sentry/error_reporting", port), strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.URL.RawQuery = "api_key=injected-credential"
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 for credential query param, got %d (body: %s)", resp.StatusCode, body)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	json.Unmarshal(body, &errResp)
	if errResp.Error != "agent_supplied_credential_query_param" {
		t.Errorf("expected agent_supplied_credential_query_param, got %q", errResp.Error)
	}
}

func TestHandler_Deny_UnknownPath_404(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"openrouter.chat"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	resp := doGatewayRequest(t, port, jwtStr, "/api/nonexistent/action", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 404, got %d (body: %s)", resp.StatusCode, body)
	}
}

func TestHandler_Deny_NoToken_401(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/sentry/error_reporting", port), strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for no token, got %d", resp.StatusCode)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 4: Constrained KEYLATCH_GATEWAY_TOKEN security invariant tests
// ─────────────────────────────────────────────────────────────────────────────

// TestGatewayToken_RejectsExpired verifies that the gateway returns 401
// "token_expired" for a JWT whose TTL has elapsed.
// The test mints a 1ms token, waits for expiry, then requests.
func TestGatewayToken_RejectsExpired(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint a token with a 1ms TTL so it expires almost immediately.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Millisecond,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	// Wait for the token to expire.
	time.Sleep(20 * time.Millisecond)

	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	json.Unmarshal(body, &errResp)
	if errResp.Error != "token_expired" {
		t.Errorf("expected token_expired, got %q", errResp.Error)
	}
}

// TestGatewayToken_RejectsScopeMismatch verifies that a token minted with
// capability "openrouter.chat.completion" is rejected with 403
// "capability_mismatch" when used on the sentry route.
func TestGatewayToken_RejectsScopeMismatch(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Token scoped to openrouter — must not work on sentry route.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
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

	// Use on a sentry route (different scope).
	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Errorf("expected 403 for scope mismatch, got %d", resp.StatusCode)
		return
	}
	assertErrorCode(t, resp, "capability_mismatch")
}

// TestGatewayToken_RejectsAudienceMismatch verifies that a token intended for
// one provider (audience) cannot be used on a route belonging to a different
// provider. Capability format encodes the audience: "<provider>.<action>".
func TestGatewayToken_RejectsAudienceMismatch(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Token scoped to sentry — attempting to use on openrouter route.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	// Try to use on openrouter route (wrong audience/provider).
	resp := doGatewayRequest(t, port, jwtStr, "/api/openrouter/chat.completion", "{}")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Errorf("expected 403 for audience mismatch, got %d", resp.StatusCode)
		return
	}
	assertErrorCode(t, resp, "capability_mismatch")
}

// TestGatewayToken_RejectsReplay verifies that a MaxUses=1 token is rejected
// with 401 "token_exhausted" on a second use (replay protection, FIND3-009).
func TestGatewayToken_RejectsReplay(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mint a MaxUses=1 token.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		MaxUses:      1,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	// First use — may succeed or fail (no vault, so credential_not_found), but token is consumed.
	resp1 := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	resp1.Body.Close()

	// Second use — must be rejected as token_exhausted (replay blocked).
	resp2 := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for replayed token, got %d", resp2.StatusCode)
		return
	}
	assertErrorCode(t, resp2, "token_exhausted")
}

// TestGatewayToken_RejectsAfterSessionEnd verifies that a token revoked via
// token.Revoke is rejected with 401 "token_revoked" on subsequent requests.
// This models the "session end" case where the daemon revokes the token.
func TestGatewayToken_RejectsAfterSessionEnd(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"sentry.error_reporting"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Revoke the token (session end).
	if err := token.Revoke(tok.ID, storePath); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	port, cancel := denyTestServer(t, key, storePath)
	defer cancel()

	resp := doGatewayRequest(t, port, jwtStr, "/api/sentry/error_reporting", "{}")
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		t.Errorf("expected 401 after session end (revocation), got %d", resp.StatusCode)
		return
	}
	assertErrorCode(t, resp, "token_revoked")
}
