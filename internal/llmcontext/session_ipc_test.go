package llmcontext_test

// session_ipc_test.go — EPIC-05 Task 2
//
// Tests for the IsLLMSession priority chain (ticket → IPC → env signals)
// and the SessionServer/SessionRegistry.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortSocketPath returns a socket path short enough for macOS (104-char limit).
// macOS limits Unix socket paths to 104 characters including the null terminator.
// t.TempDir() paths can exceed this, so we use /tmp with a short name instead.
// The temp directory is registered for cleanup via t.Cleanup.
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	// Use os.MkdirTemp to get a short base dir under /tmp.
	// This avoids the deep /var/folders/... paths that t.TempDir() produces.
	dir, err := os.MkdirTemp("", "kl-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir + "/" + name
}

// waitForSocket polls until the UDS at path is connectable or the test times out.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become available within 2s", path)
}

// udsHTTPClient returns an http.Client that dials socketPath over UDS.
func udsHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 2 * time.Second,
	}
}

// ipcGET performs GET over UDS and decodes the LLMSessionResponse.
func ipcGET(t *testing.T, client *http.Client, urlPath string) llmcontext.LLMSessionResponse {
	t.Helper()
	resp, err := client.Get("http://keylatchd" + urlPath)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out llmcontext.LLMSessionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// ipcPOST performs POST over UDS with a JSON body.
func ipcPOST(t *testing.T, client *http.Client, urlPath, bodyJSON string) {
	t.Helper()
	resp, err := client.Post("http://keylatchd"+urlPath, "application/json", bytes.NewBufferString(bodyJSON))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// ipcDELETE performs DELETE over UDS.
func ipcDELETE(t *testing.T, client *http.Client, urlPath string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, "http://keylatchd"+urlPath, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// startSessionServer starts a session server on socketPath and returns a cancel func.
func startSessionServer(t *testing.T, socketPath string) (*llmcontext.SessionRegistry, context.CancelFunc) {
	t.Helper()
	key := makeSigningKey(t)
	registry := llmcontext.NewSessionRegistry()

	srv, err := llmcontext.NewSessionServer(socketPath, key, registry)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Listen(ctx) }()
	t.Cleanup(func() {
		cancel()
		// The server's Listen() removes the socket on shutdown; best-effort here.
		_ = os.Remove(socketPath)
	})

	waitForSocket(t, socketPath)
	return registry, cancel
}

// ── IsLLMSession priority chain tests ────────────────────────────────────────

// TestIsLLMSession_TicketTakesPrecedence verifies Priority 1: when
// KEYLATCH_LLM_TICKET is set, IsLLMSession returns true regardless of other signals.
func TestIsLLMSession_TicketTakesPrecedence(t *testing.T) {
	t.Parallel()
	env := lookup(map[string]string{
		"KEYLATCH_LLM_TICKET": "some-ticket-value",
	})
	assert.True(t, llmcontext.IsLLMSession(env),
		"IsLLMSession must return true when KEYLATCH_LLM_TICKET is set (Priority 1)")
}

// TestIsLLMSession_TicketEmpty_FallsThrough verifies an empty ticket falls through.
func TestIsLLMSession_TicketEmpty_FallsThrough(t *testing.T) {
	t.Parallel()
	env := lookup(map[string]string{"KEYLATCH_LLM_TICKET": ""})
	assert.False(t, llmcontext.IsLLMSession(env),
		"empty KEYLATCH_LLM_TICKET must fall through to lower-priority checks")
}

// TestIsLLMSession_FailsClosed_AmbiguousState verifies that IsLLMSession returns
// true when the daemon socket is set but the daemon is not reachable.
// Fail-closed contract: ambiguous/error state → return true (assume LLM session).
func TestIsLLMSession_FailsClosed_AmbiguousState(t *testing.T) {
	t.Parallel()
	env := lookup(map[string]string{
		"KEYLATCH_DAEMON_SOCKET": "/tmp/kl-nonexistent-7x9z2.sock",
	})
	assert.True(t, llmcontext.IsLLMSession(env),
		"IsLLMSession must fail-closed (return true) when daemon socket is unreachable")
}

// TestIsLLMSession_KeylatchdIPCConfirmsSession verifies Priority 2: a running
// session server that reports active=false returns false (no session).
func TestIsLLMSession_KeylatchdIPCConfirmsSession(t *testing.T) {
	socketPath := shortSocketPath(t, "s.sock")
	registry, _ := startSessionServer(t, socketPath)

	// No PID registered → daemon reports active=false → IsLLMSession falls
	// through env signals → no signals → false.
	envNotRegistered := func(k string) string {
		if k == "KEYLATCH_DAEMON_SOCKET" {
			return socketPath
		}
		return ""
	}
	assert.False(t, llmcontext.IsLLMSession(envNotRegistered),
		"IsLLMSession must return false when daemon says no session active and no env signals")

	// Verify registry operations directly.
	registry.Register(42424242, "test-agent")
	active, agent := registry.IsActive(42424242)
	assert.True(t, active)
	assert.Equal(t, "test-agent", agent)

	registry.Deregister(42424242)
	active, _ = registry.IsActive(42424242)
	assert.False(t, active)
}

// ── SessionRegistry tests ─────────────────────────────────────────────────────

// TestSessionRegistry_Basic verifies basic registry CRUD operations.
func TestSessionRegistry_Basic(t *testing.T) {
	t.Parallel()
	reg := llmcontext.NewSessionRegistry()

	active, agent := reg.IsActive(1234)
	assert.False(t, active)
	assert.Empty(t, agent)

	reg.Register(1234, "claude-code")
	active, agent = reg.IsActive(1234)
	assert.True(t, active)
	assert.Equal(t, "claude-code", agent)

	// Overwrite with different agent.
	reg.Register(1234, "cursor")
	active, agent = reg.IsActive(1234)
	assert.True(t, active)
	assert.Equal(t, "cursor", agent)

	reg.Deregister(1234)
	active, _ = reg.IsActive(1234)
	assert.False(t, active)

	// Deregister non-existent PID is a no-op.
	reg.Deregister(9999)
}

// ── SessionServer HTTP endpoint tests ────────────────────────────────────────

// TestSessionServer_GetNotRegistered verifies GET /v1/llm-session returns
// active=false and _schema:"v1" for an unregistered PID.
func TestSessionServer_GetNotRegistered(t *testing.T) {
	socketPath := shortSocketPath(t, "s.sock")
	startSessionServer(t, socketPath)

	client := udsHTTPClient(socketPath)
	resp := ipcGET(t, client, "/v1/llm-session?pid=99999")
	assert.Equal(t, "v1", resp.Schema,
		"_schema must be 'v1' (load-bearing for EPIC-21/23)")
	assert.False(t, resp.Active,
		"unregistered PID must not be active")
}

// TestSessionServer_RegisterAndQuery verifies the POST → GET flow and socket permissions.
func TestSessionServer_RegisterAndQuery(t *testing.T) {
	socketPath := shortSocketPath(t, "s.sock")
	startSessionServer(t, socketPath)

	// Verify the socket is mode 0600 — world access must be blocked.
	// Windows uses ACL-based permissions; POSIX mode bits are not enforced there.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(socketPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "session socket must be mode 0600")
	}

	client := udsHTTPClient(socketPath)

	// POST to register.
	ipcPOST(t, client, "/v1/llm-session", `{"pid":55555,"agent":"aider"}`)

	// GET — must be active.
	resp := ipcGET(t, client, "/v1/llm-session?pid=55555")
	assert.Equal(t, "v1", resp.Schema)
	assert.True(t, resp.Active)
	assert.Equal(t, "aider", resp.Agent)

	// DELETE to deregister.
	ipcDELETE(t, client, "/v1/llm-session?pid=55555")

	// GET — must be inactive.
	resp = ipcGET(t, client, "/v1/llm-session?pid=55555")
	assert.Equal(t, "v1", resp.Schema)
	assert.False(t, resp.Active)
}

// TestSessionServer_SchemaV1 verifies that all responses carry _schema:"v1".
// This is load-bearing for EPIC-21 and EPIC-23.
func TestSessionServer_SchemaV1(t *testing.T) {
	socketPath := shortSocketPath(t, "s.sock")
	startSessionServer(t, socketPath)

	client := udsHTTPClient(socketPath)
	resp := ipcGET(t, client, "/v1/llm-session?pid=1")
	assert.Equal(t, "v1", resp.Schema,
		"_schema must be 'v1' in all GET /v1/llm-session responses (EPIC-21/23 contract)")
}
