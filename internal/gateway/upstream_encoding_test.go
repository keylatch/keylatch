package gateway_test

import (
	"bytes"
	"compress/gzip"
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
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

const leakedUpstreamKey = "sk-or-leaked0123456789abcdefghijklmnop"

// gatewayWithUpstream starts a gateway whose openrouter route reaches
// upstream through a transport that never asks for or undoes compression,
// so the gateway sees exactly what the upstream sends.
func gatewayWithUpstream(t *testing.T, upstream http.Handler) (string, string) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat.completion"},
		TTL:          time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	raw := &http.Transport{DisableCompression: true}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(up.URL, "http://")
		req.Host = req.URL.Host
		return raw.RoundTrip(req)
	})
	port := freePort(t)
	srv, err := gateway.New(gateway.ServerOptions{
		Bind:               fmt.Sprintf("127.0.0.1:%d", port),
		SigningKey:         key,
		ApprovalsDir:       filepath.Join(dir, "approvals"),
		TokenStorePath:     storePath,
		Env:                llmcontext.DefaultLookup,
		Vault:              &stubVaultReader{values: map[string][]byte{"default/ai/openrouter/api_key": []byte("sk-or-real-credential-0123456789abcdef")}},
		OverrideHTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	return fmt.Sprintf("http://127.0.0.1:%d/api/openrouter/chat.completion", port), jwtStr
}

// sendRaw posts through the gateway without the client transport touching
// compression, and returns the response exactly as the gateway wrote it.
func sendRaw(t *testing.T, url, jwt string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestGatewayForwardsOnlyAllowedHeaders(t *testing.T) {
	var got http.Header
	url, jwt := gatewayWithUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	resp, _ := sendRaw(t, url, jwt, map[string]string{
		"Accept-Encoding":   "gzip, br",
		"Range":             "bytes=0-10",
		"If-Range":          "etag",
		"Cookie":            "session=abc",
		"Anthropic-Version": "2023-06-01",
		"Anthropic-Api-Key": "agent-supplied",
		"Openai-Beta":       "assistants=v2",
		"X-Custom":          "anything",
		"Accept":            "application/json",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, h := range []string{"Accept-Encoding", "Range", "If-Range", "Cookie", "Anthropic-Api-Key", "X-Custom"} {
		if v := got.Get(h); v != "" {
			t.Errorf("upstream received %s: %q", h, v)
		}
	}
	for h, want := range map[string]string{"Anthropic-Version": "2023-06-01", "Openai-Beta": "assistants=v2", "Accept": "application/json", "Content-Type": "application/json"} {
		if v := got.Get(h); v != want {
			t.Errorf("upstream %s = %q, want %q", h, v, want)
		}
	}
}

func TestGatewayRedactsCompressedUpstreamResponse(t *testing.T) {
	url, jwt := gatewayWithUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`{"api_key":"` + leakedUpstreamKey + `","note":"` + leakedUpstreamKey + `"}`))
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	resp, body := sendRaw(t, url, jwt, map[string]string{"Accept-Encoding": "gzip"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Fatalf("response still encoded: %q", enc)
	}
	if bytes.Contains(body, []byte(leakedUpstreamKey)) {
		t.Fatalf("secret passed through a compressed response: %s", body)
	}
	if !bytes.Contains(body, []byte(`"note"`)) {
		t.Fatalf("response is not the decoded body: %q", body)
	}
}

func TestGatewayRefusesUnsupportedUpstreamEncoding(t *testing.T) {
	url, jwt := gatewayWithUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("opaque-" + leakedUpstreamKey))
	}))
	resp, body := sendRaw(t, url, jwt, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(leakedUpstreamKey)) || bytes.Contains(body, []byte("opaque-")) {
		t.Fatalf("refused response leaked the upstream body: %s", body)
	}
}
