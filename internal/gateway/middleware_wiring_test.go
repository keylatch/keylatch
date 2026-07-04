package gateway_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// startTestServer boots a gateway Server on a free localhost port and returns
// the resolved base URL. The server is shut down via the returned context cancel.
func startTestServer(t *testing.T) (baseURL string, cancel context.CancelFunc) {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Reserve a free port; bind explicitly so we know the URL upfront.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	dir := t.TempDir()
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: dir + "/tokens.json",
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx)
	}()
	// Wait briefly for the listener to come up.
	deadline := time.Now().Add(2 * time.Second)
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		c := &http.Client{Timeout: 100 * time.Millisecond}
		resp, err := c.Get(url + "/health")
		if err == nil {
			_ = resp.Body.Close()
			return url, cancelFn
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancelFn()
	t.Fatal("server did not start within 2s")
	return "", nil
}

// TestServerWiring_AuthBlocker_ApiKeyQueryParamRejected asserts that an
// api_key query parameter is rejected at the server boundary.
func TestServerWiring_AuthBlocker_ApiKeyQueryParamRejected(t *testing.T) {
	baseURL, cancel := startTestServer(t)
	defer cancel()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/openai/models?api_key=sk-leaked", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from authBlockerMiddleware (api_key); got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "agent_supplied_credential_query_param") {
		t.Fatalf("expected api_key blocker error code; got body=%s", body)
	}
}

// TestServerWiring_HostOverrideBlocker_XForwardedHostRejected asserts that an
// X-Forwarded-Host header is rejected at the server boundary.
func TestServerWiring_HostOverrideBlocker_XForwardedHostRejected(t *testing.T) {
	baseURL, cancel := startTestServer(t)
	defer cancel()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/openai/models", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from hostOverrideBlockerMiddleware; got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "host_override_header_blocked") {
		t.Fatalf("expected host override blocker error code; got body=%s", body)
	}
}

// TestServerWiring_HealthEndpointUnaffected asserts that /health (a gateway-
// internal route) is NOT wrapped by the auth/host blocker middlewares — it
// must remain reachable without authentication, since it is a value-free
// liveness probe.
func TestServerWiring_HealthEndpointUnaffected(t *testing.T) {
	baseURL, cancel := startTestServer(t)
	defer cancel()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Get /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /health to return 200; got %d", resp.StatusCode)
	}
}
