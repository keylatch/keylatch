package cli

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
)

// fileVaultEnv configures a hermetic file backend and returns its config/env.
func fileVaultEnv(t *testing.T) (config.Config, func(string) string) {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	dir := t.TempDir()
	krPath := testutil.SetupTestKeyring(t)
	t.Setenv("KEYLATCH_KEYRING_PATH", krPath)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	env := func(k string) string {
		switch k {
		case "KEYLATCH_BACKEND":
			return "file"
		case "KEYLATCH_DATA_DIR":
			return dir
		case "KEYLATCH_KEYRING_PATH":
			return krPath
		}
		return ""
	}
	return config.Config{Backend: "file", DataDir: dir}, env
}

// TestGatewayVault_ConnectedCredentialReachesUpstream covers the production
// wiring: a key stored the way `keylatch connect` stores it must be read by the
// reader `gateway up` builds and injected into the upstream request.
func TestGatewayVault_ConnectedCredentialReachesUpstream(t *testing.T) {
	cfg, env := fileVaultEnv(t)
	ctx := context.Background()
	if err := registry.InitFromConfig(ctx, env); err != nil {
		t.Fatalf("registry init: %v", err)
	}

	const apiKey = "sk-test-gateway-wiring-0123456789"
	if _, err := connections.Connect(ctx, "openai", connections.ConnectOptions{
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte(apiKey)},
	}, newDispatchedStore(cfg, env)); err != nil {
		t.Fatalf("connect openai: %v", err)
	}

	reader, err := newGatewayVaultReader(ctx, cfg, env)
	if err != nil {
		t.Fatalf("newGatewayVaultReader: %v", err)
	}

	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()
	toUpstream := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
		req.Host = req.URL.Host
		return http.DefaultTransport.RoundTrip(req)
	})

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	stateDir := t.TempDir()
	storePath := filepath.Join(stateDir, "tokens.json")
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openai.chat_completion"},
		TTL:          time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	bind := freeLoopbackAddr(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:               bind,
		SigningKey:         key,
		ApprovalsDir:       filepath.Join(stateDir, "approvals"),
		TokenStorePath:     storePath,
		Env:                env,
		Vault:              reader,
		OverrideHTTPClient: &http.Client{Transport: toUpstream, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(srvCtx) //nolint:errcheck // stopped via cancel
	waitListening(t, bind)

	req, _ := http.NewRequest(http.MethodPost, "http://"+bind+"/api/openai/chat_completion",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200", resp.StatusCode)
	}
	if gotAuth != "Bearer "+apiKey {
		t.Fatalf("upstream Authorization = %q, want the connected API key", gotAuth)
	}
}

func TestNewGatewayVaultReader_UnknownBackendFails(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	_, err := newGatewayVaultReader(context.Background(),
		config.Config{Backend: "no-such-backend"}, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("gateway did not start listening on %s", addr)
}
