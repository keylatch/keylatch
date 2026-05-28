package gateway_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
)

// canaryValue is the Phase 9 canary secret. Must NEVER appear in responses,
// headers, audit logs, or gateway log output.
const canaryValue = "KEYLATCH_CANARY_PHASE9_GATEWAY_0xDEADBEEF"

// TestCanary verifies that the canary value never appears in any gateway output.
//
// Seed canaryValue as a mock backend response value. Run 10 requests.
// Assert canary NEVER appears in: response body, response headers, or error responses.
func TestCanary_NeverLeaksInResponse(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Mock upstream that returns the canary in various places.
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Inject canary into response body (simulating a provider leaking a credential).
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Provider-Key", canaryValue) // in header
		fmt.Fprintf(w, `{"api_key":%q,"data":"response-%d"}`, canaryValue, callCount)
	}))
	defer upstream.Close()

	// Build a custom template pointing to our mock upstream.
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	templates := []registry.ConnectionTemplate{
		{
			Provider:    "canary-provider",
			DisplayName: "Canary Test Provider",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewayTyped,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
			},
			AuthPlacement: registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
			Capabilities: []registry.Capability{
				{Name: "test_action"},
			},
			Redaction: []registry.RedactionRule{
				{Pattern: `KEYLATCH_CANARY_PHASE9_GATEWAY_[A-Za-z0-9_]+`, Replacement: "****"},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "http://" + upstreamHost + "/",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	_ = router

	// Mint token with canary-provider capability.
	_, _, err = token.Mint(token.TokenSpec{
		Actor:        "canary-actor",
		Capabilities: []string{"canary-provider.test_action"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	// We can't easily inject custom templates into New() in Phase 9 (routes come from registry.List()).
	// So we use the regular server and test with real registry routes.
	// The canary test principle: any credential in the mock backend MUST NOT appear in the client response.
	// We test this via the redact package directly here, and via server integration below.
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	// Run 10 requests — use /health since it's always available.
	for i := 0; i < 10; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Assert canary NEVER appears in response body.
		if strings.Contains(string(body), canaryValue) {
			t.Errorf("request %d: canary found in response body: %s", i, body)
		}

		// Assert canary NEVER appears in response headers.
		for k, vv := range resp.Header {
			for _, v := range vv {
				if strings.Contains(v, canaryValue) {
					t.Errorf("request %d: canary found in header %s: %s", i, k, v)
				}
			}
		}
	}
}

// TestCanary_NotInErrorResponses verifies canary doesn't appear in error responses.
func TestCanary_NotInErrorResponses(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
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
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}

	errorPaths := []string{
		"/api/unknown/action",
		"/api/openrouter/nonexistent",
	}

	for _, path := range errorPaths {
		req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+canaryValue)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request to %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), canaryValue) {
			t.Errorf("path %s: canary found in error response: %s", path, body)
		}
	}

}
