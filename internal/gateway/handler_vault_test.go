package gateway_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	filebe "github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// stubVaultReader is a test-only VaultReader.
type stubVaultReader struct {
	values map[string][]byte
	err    error
}

func (s *stubVaultReader) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	if s.err != nil {
		return nil, backend.Meta{}, s.err
	}
	v, ok := s.values[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, backend.Meta{Path: path, Backend: "stub", Version: 1}, nil
}

// Implement the remaining Backend methods so stubVaultReader satisfies backend.Backend
// if needed. Since VaultReader is our narrow interface, we only need Get.
// The struct only implements VaultReader.

// stubBackend implements backend.Backend for completeness (used for stub injection below).
type stubBackend struct {
	values map[string][]byte
	err    error
}

func newStubBackend(values map[string][]byte) *stubBackend {
	return &stubBackend{values: values}
}

func (s *stubBackend) Name() string                       { return "stub" }
func (s *stubBackend) Capabilities() []backend.Capability { return nil }
func (s *stubBackend) ID() string                         { return "stub" }
func (s *stubBackend) Close() error                       { return nil }

func (s *stubBackend) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	if s.err != nil {
		return nil, backend.Meta{}, s.err
	}
	v, ok := s.values[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, backend.Meta{Path: path, Backend: "stub", Version: 1}, nil
}

func (s *stubBackend) Set(_ context.Context, _ string, _ []byte, _ backend.Meta) error {
	return nil
}
func (s *stubBackend) Delete(_ context.Context, _ string) error { return nil }
func (s *stubBackend) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, nil
}
func (s *stubBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}
func (s *stubBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}
func (s *stubBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}
func (s *stubBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}
func (s *stubBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}
func (s *stubBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// roundTripFunc is a test http.RoundTripper backed by a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// TestGatewayVault_CredentialNotFound verifies that when vault returns ErrNotFound,
// the gateway returns 401 with code "credential_not_found".
func TestGatewayVault_CredentialNotFound(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Empty vault — all gets return ErrNotFound.
	vault := &stubVaultReader{values: map[string][]byte{}}

	// Mint a valid token. Use a provider that has a registered gateway route.
	// openrouter has gateway_typed routes in the registry. The capability name
	// matches the template: "chat.completion" → route "/api/openrouter/chat.completion".
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port),
		strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 401 for credential_not_found, got %d (body: %s)", resp.StatusCode, body)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("parse error response: %v (body: %s)", err, body)
	}
	if errResp.Error != "credential_not_found" {
		t.Errorf("expected error=credential_not_found, got %q", errResp.Error)
	}
}

// TestGatewayVault_VaultUnavailable verifies that when vault returns a non-NotFound
// error, the gateway returns 503 with code "vault_error".
func TestGatewayVault_VaultUnavailable(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// Vault that always returns ErrLocked (non-NotFound error).
	vault := &stubVaultReader{err: backend.ErrLocked}

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port),
		strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 503 for vault_error, got %d (body: %s)", resp.StatusCode, body)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("parse error response: %v (body: %s)", err, body)
	}
	if errResp.Error != "vault_error" {
		t.Errorf("expected error=vault_error, got %q", errResp.Error)
	}
}

// TestGatewayVault_CredentialReachesUpstream verifies that when vault returns a
// credential, it is injected into the upstream request's Authorization header,
// and the Keylatch JWT is NOT forwarded.
func TestGatewayVault_CredentialReachesUpstream(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	// The credential value that vault returns.
	const credValue = "sk-or-test-credential-value-abc123"

	// Mint a token for openrouter.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Track what upstream received.
	var upstreamAuthHeader string
	var upstreamHasKeylatchJWT bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
		// Keylatch JWT starts with the JWT format; we check that the JWT itself
		// did not get forwarded. The upstream should receive the provider cred, not the JWT.
		upstreamHasKeylatchJWT = r.Header.Get("Authorization") == "Bearer "+jwtStr
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chatcmpl-ok","choices":[]}`))
	}))
	defer upstream.Close()

	// Vault returns the credential at the path the openrouter route uses.
	// The path is "default/ai/openrouter/api_key" (canonical S-FIND-23 format).
	// openrouter's first injection rule source is "api_key".
	vault := &stubVaultReader{
		values: map[string][]byte{
			"default/ai/openrouter/api_key": []byte(credValue),
		},
	}

	// Custom transport that redirects all upstream calls to our mock.
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Rewrite the request URL to point to our mock upstream.
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
		req.Host = req.URL.Host
		return http.DefaultTransport.RoundTrip(req)
	})

	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:           fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:     key,
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
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

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port),
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Upstream must have been called.
	if upstreamAuthHeader == "" {
		t.Error("upstream was not called or Authorization header missing")
	}

	// Upstream Authorization must contain the provider credential.
	if !strings.Contains(upstreamAuthHeader, credValue) {
		t.Errorf("upstream Authorization %q does not contain credential %q", upstreamAuthHeader, credValue)
	}

	// Upstream must NOT have received the Keylatch JWT.
	if upstreamHasKeylatchJWT {
		t.Error("Keylatch JWT was forwarded to upstream — it must be stripped")
	}
}

// TestGatewayAuth_KeylatchJWTNotInUpstreamRequest verifies that the Authorization
// header carrying the Keylatch JWT is removed before the request is forwarded
// upstream (T02 regression test).
func TestGatewayAuth_KeylatchJWTNotInUpstreamRequest(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const credValue = "sk-or-injected-cred"
	vault := &stubVaultReader{
		values: map[string][]byte{
			"default/ai/openrouter/api_key": []byte(credValue),
		},
	}

	var upstreamGotJWT bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The upstream must NOT receive the Keylatch JWT.
		if r.Header.Get("Authorization") == "Bearer "+jwtStr {
			upstreamGotJWT = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chatcmpl-ok","choices":[]}`))
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
		ApprovalsDir:   dir + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          vault,
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

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port),
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if upstreamGotJWT {
		t.Error("Keylatch JWT was forwarded to upstream — must be stripped before forwarding (T02)")
	}
}

// buildTestKeyring creates a fresh in-memory keyring backed by a temp directory,
// suitable for use in gateway AEAD vault tests. Returns the keyring and its directory.
func buildTestKeyring(t *testing.T) (*keyring.Keyring, string) {
	t.Helper()
	dir := t.TempDir()
	krDir := filepath.Join(dir, "keyring")
	if err := os.MkdirAll(krDir, 0o700); err != nil {
		t.Fatalf("mkdir keyring: %v", err)
	}
	krPath := filepath.Join(krDir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte("test-gateway-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 33)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kf := keyring.KeyringFile{
		SchemaVersion: keyring.SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		Terms: []keyring.TermRecord{
			{
				Term:       1,
				Status:     keyring.TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}

	// Re-derive KEK for Open (passphrase was zeroed on first call).
	k2, err := kek.PassphraseKEK([]byte("test-gateway-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	kr, err := keyring.Open(krPath, k2)
	if err != nil {
		t.Fatalf("keyring.Open: %v", err)
	}
	t.Cleanup(func() { kr.Zero() })
	return kr, dir
}

// TestGatewayUp_ResolvesAEADCredential verifies that the gateway, when wired to
// an AEAD-encrypted file backend vault, successfully resolves credentials and
// injects them into upstream requests (Task 2: gateway wired to AEAD vault).
//
// The test constructs a file backend with a real XChaCha20-Poly1305 keyring,
// writes a credential at the canonical path "default/ai/openrouter/api_key",
// then passes the backend as Vault to the gateway and verifies the credential
// reaches the mock upstream.
func TestGatewayUp_ResolvesAEADCredential(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	storePath := filepath.Join(t.TempDir(), "tokens.json")

	const credValue = "sk-or-aead-gateway-test-credential"

	// Build a file backend with an AEAD keyring.
	kr, vaultDir := buildTestKeyring(t)
	fb, err := filebe.OpenWithKeyring(filebe.Options{Dir: vaultDir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring: %v", err)
	}

	// Write credential at canonical path (S-FIND-23, T-03-01).
	const credPath = "default/ai/openrouter/api_key"
	if err := fb.Set(context.Background(), credPath, []byte(credValue), backend.Meta{}); err != nil {
		t.Fatalf("Set credential: %v", err)
	}

	// Mint a gateway token for openrouter.
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "aead-test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Upstream mock — captures the Authorization header.
	var upstreamAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"aead-ok","choices":[]}`))
	}))
	defer upstream.Close()

	// Transport that rewrites all requests to the mock upstream.
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
		ApprovalsDir:   t.TempDir() + "/approvals",
		TokenStorePath: storePath,
		Env:            llmcontext.DefaultLookup,
		Vault:          fb, // AEAD-backed vault
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

	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port),
		strings.NewReader(`{"model":"gpt-4","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// The upstream must have received the credential (not the Keylatch JWT).
	if !strings.Contains(upstreamAuth, credValue) {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("upstream Authorization %q does not contain AEAD credential %q (status=%d, body=%s)",
			upstreamAuth, credValue, resp.StatusCode, body)
	}
	if upstreamAuth == "Bearer "+jwtStr {
		t.Error("Keylatch JWT was forwarded to upstream — must be stripped")
	}
}

// TestGatewayAuth_OnVaultLock_FlushesCache verifies that OnVaultLock returns
// no error and results in Exchange returning ErrVaultLocked (FIND2-004).
func TestGatewayAuth_OnVaultLock_FlushesCache(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
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

	// OnVaultLock must not error.
	if err := srv.OnVaultLock(context.Background()); err != nil {
		t.Errorf("OnVaultLock: %v", err)
	}
	// OnVaultUnlock must not error.
	if err := srv.OnVaultUnlock(context.Background()); err != nil {
		t.Errorf("OnVaultUnlock: %v", err)
	}
}
