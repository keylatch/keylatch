package gateway_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

func testSigningKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestServer_StartsOn127001(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()

	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           "127.0.0.1:0",
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: dir + "/tokens.json",
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Give the server a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Logf("Serve error (acceptable): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for server to stop")
	}
}

func TestServer_RefusesNonLoopbackBind(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()

	_, err := gateway.New(gateway.ServerOptions{
		Bind:              "0.0.0.0:7878",
		SigningKey:        key,
		ApprovalsDir:      dir + "/approvals",
		TokenStorePath:    dir + "/tokens.json",
		AllowExternalBind: false,
		Env:               llmcontext.DefaultLookup,
	})
	if err == nil {
		t.Error("expected error for non-loopback bind without AllowExternalBind")
	}
}

func TestServer_RefusesNonLoopback_InLLMSession(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()

	// Simulate LLM session.
	llmEnv := func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}

	_, err := gateway.New(gateway.ServerOptions{
		Bind:              "0.0.0.0:7878",
		SigningKey:        key,
		ApprovalsDir:      dir + "/approvals",
		TokenStorePath:    dir + "/tokens.json",
		AllowExternalBind: true, // even with opt-in, LLM session should block
		Env:               llmEnv,
	})
	if err == nil {
		t.Error("expected error: non-loopback bind in LLM session should be refused even with AllowExternalBind")
	}
}

func TestServer_Health(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()

	// Find a free port.
	port := freePort(t)

	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: dir + "/tokens.json",
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	go func() {
		close(ready)
		srv.Serve(ctx) //nolint:errcheck
	}()
	<-ready
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()
	port := freePort(t)

	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: dir + "/tokens.json",
		Env:            llmcontext.DefaultLookup,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("Serve completed with: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("graceful shutdown timed out")
	}
}

// freePort finds an available TCP port by listening on :0.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
