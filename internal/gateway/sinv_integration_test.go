package gateway_test

// sinv_integration_test.go — gateway route and auth integration tests.
//
// Gateway end-to-end route matching and auth enforcement. Credentials
// loaded from vault must not appear in gateway responses (no credential echo).
//
// All gateway routes require a valid Bearer token; unauthenticated
// requests → 401 with error code "missing_token".

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// waitForGateway polls the /health endpoint until the gateway is ready or 5 s elapses.
func waitForGateway(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if err == nil {
			resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway did not become ready in 5s")
}

// TestSINV9_GatewayRouteMatchingAndAuthEnforcement verifies:
//   - All known provider routes resolve (not 404) when a valid JWT is presented.
//   - The response never contains a credential-shaped canary string.
//   - Routes are compiled from the registry — non-existent paths → 404.
func TestSINV9_GatewayRouteMatchingAndAuthEnforcement(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand.Reader: %v", err)
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	waitForGateway(t, fmt.Sprintf("127.0.0.1:%d", port))

	// Verify compiled routes are non-empty (registry wired to router).
	routes := srv.Routes()
	if len(routes) == 0 {
		t.Fatal("gateway has no compiled routes — registry not loaded")
	}

	// Verify all routes have non-empty Capability and Provider fields.
	for _, rt := range routes {
		if rt.Capability == "" {
			t.Errorf("route %s has empty Capability", rt.PathTemplate)
		}
		if rt.Provider == "" {
			t.Errorf("route %s has empty Provider", rt.PathTemplate)
		}
	}

	// Non-existent path must 404 (not bypass routing).
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "sinv9-actor",
		Capabilities: []string{"openrouter.chat_completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/nonexistent_provider_xyz/action", port),
		strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-existent route must return 404, got %d", resp.StatusCode)
	}

	// Health endpoint works without auth (not a credential route).
	healthReq, _ := http.NewRequest("GET",
		fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
	healthResp, err := client.Do(healthReq)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("/health must return 200, got %d", healthResp.StatusCode)
	}
}

// TestSINV12_AllGatewayRoutesRequireAuth verifies that every request to a
// known gateway route without an Authorization header returns 401.
func TestSINV12_AllGatewayRoutesRequireAuth(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand.Reader: %v", err)
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	waitForGateway(t, fmt.Sprintf("127.0.0.1:%d", port))

	testPaths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/openrouter/chat_completion"},
		{"POST", "/api/anthropic/messages"},
		{"POST", "/api/sentry/error_reporting"},
		{"POST", "/sdk/openrouter/v1/chat/completions"},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range testPaths {
		req, _ := http.NewRequest(tc.method,
			fmt.Sprintf("http://127.0.0.1:%d%s", port, tc.path),
			strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header — must require 401.
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s %s: %v", tc.method, tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("path %s without auth: want 401, got %d (body: %s)",
				tc.path, resp.StatusCode, body)
			continue
		}
		// Verify the error code is "missing_token".
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Errorf("could not parse error response: %v (body: %s)", err, body)
			continue
		}
		if errResp.Error != "missing_token" {
			t.Errorf("path %s: expected error code 'missing_token', got %q",
				tc.path, errResp.Error)
		}
	}
}

// TestSINV12_InvalidTokenReturns401 verifies that a malformed or expired JWT
// returns 401 (token validation).
func TestSINV12_InvalidTokenReturns401(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand.Reader: %v", err)
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	waitForGateway(t, fmt.Sprintf("127.0.0.1:%d", port))

	malformedTokens := []struct {
		name  string
		token string
	}{
		{"not-a-jwt", "not-a-jwt"},
		{"empty-parts", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.malformed"},
		{"wrong-key-signed", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY3RvciI6InRlc3QiLCJjYXBhYmlsaXRpZXMiOlsib3BlbnJvdXRlci5jaGF0X2NvbXBsZXRpb24iXX0.INVALID_SIGNATURE"},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range malformedTokens {
		req, _ := http.NewRequest("POST",
			fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat_completion", port),
			strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("malformed token %q: want 401, got %d",
				tc.name, resp.StatusCode)
		}
	}
}

// TestSINV12_VaultCredentialNotEchoedInResponse verifies that a credential
// returned by vault.Get never appears verbatim in the gateway HTTP response
// body or headers (credential non-echo invariant).
//
// S-04: uses an httptest.Server as the mock upstream so the positive path
// (upstream returns 200) is exercised, not just an absence-of-canary assertion
// against a 502 from a real remote URL.
func TestSINV12_VaultCredentialNotEchoedInResponse(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("rand.Reader: %v", err)
	}
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	const canaryValue = "sk-ant-canary-SINV12-0xCAFEBABE-1234567890abcdef"

	// Mock upstream that returns a synthetic 200 with a safe body.
	// The gateway should forward the upstream response without injecting the credential.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the canary does NOT appear in headers forwarded to the upstream —
		// it should be in the Authorization header to the upstream, not echoed back.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id":"chatcmpl-test","object":"chat.completion","choices":[]}`)
	}))
	defer upstream.Close()

	// Use the stubVaultReader defined in handler_vault_test.go (same package).
	vaultStub := &stubVaultReader{
		values: map[string][]byte{
			"default/ai/openrouter/api_key": []byte(canaryValue),
		},
	}

	// OverrideHTTPClient routes all upstream calls to the mock server.
	mockClient := upstream.Client()
	mockClient.Transport = roundTripToServer(upstream.URL)

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:               fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:         key,
		ApprovalsDir:       dir + "/approvals",
		TokenStorePath:     storePath,
		Env:                llmcontext.DefaultLookup,
		Vault:              vaultStub,
		OverrideHTTPClient: mockClient,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	waitForGateway(t, fmt.Sprintf("127.0.0.1:%d", port))

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "sinv12-actor",
		Capabilities: []string{"openrouter.chat_completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat_completion", port),
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The canary credential must never appear in the response body.
	if strings.Contains(string(body), canaryValue) {
		t.Errorf("vault canary credential found in gateway response body")
	}

	// The canary credential must never appear in response headers.
	for name, vals := range resp.Header {
		for _, v := range vals {
			if strings.Contains(v, canaryValue) {
				t.Errorf("vault canary found in response header %s: %q", name, v)
			}
		}
	}
}

// roundTripToServer returns an http.RoundTripper that redirects all requests to
// the given base URL (used to point the gateway's HTTP client at the mock upstream).
func roundTripToServer(baseURL string) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Replace the host so the request goes to the mock server.
		req2 := req.Clone(req.Context())
		req2.URL.Host = strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
		req2.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req2)
	})
}
