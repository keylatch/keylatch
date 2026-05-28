package llmcontext

// ipc_client.go — EPIC-05 Task 2
//
// Lightweight UDS HTTP client for querying keylatchd's LLM session endpoint.
//
// This file implements the Priority-2 check in IsLLMSession: if no ticket is
// present, the CLI can query the keylatchd sidecar via a Unix domain socket to
// check whether the current process PID is registered as an LLM session.
//
// Fail-closed contract:
//   - Any network error, timeout, or unexpected response → return (true, nil)
//     (treat as "assume LLM session" — safer than false negative).
//   - A clean "active: false" response from the daemon → return (false, nil).
//   - A clean "active: true" response from the daemon → return (true, nil).
//
// The socket path is read from the KEYLATCH_DAEMON_SOCKET env var.
// If that var is not set, the IPC check is skipped (no daemon running).
//
// S0-7: this file imports only stdlib packages. No github.com/keylatch/keylatch/internal/* deps.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// daemonSocketEnvKey is the env var that tells the CLI where to find the
// keylatchd LLM session UDS socket.
const daemonSocketEnvKey = "KEYLATCH_DAEMON_SOCKET"

// daemonIPCTimeout is the maximum time to wait for a keylatchd IPC response.
const daemonIPCTimeout = 250 * time.Millisecond

// LLMSessionResponse is the response body from GET /v1/llm-session.
// _schema is load-bearing for EPIC-21 and EPIC-23 — must be "v1".
type LLMSessionResponse struct {
	Schema string `json:"_schema"` // always "v1"
	Active bool   `json:"active"`
	Agent  string `json:"agent,omitempty"`
	Ticket string `json:"ticket,omitempty"`
}

// queryDaemonLLMSession asks the keylatchd sidecar whether pid is currently
// registered as an LLM session. The socketPath is the UDS path from the
// KEYLATCH_DAEMON_SOCKET env var.
//
// Returns (true, nil) on any error (fail-closed); (active, nil) on success.
// Returns (false, nil) only if the daemon explicitly responds with active=false.
func queryDaemonLLMSession(socketPath string, pid int) (active bool, err error) {
	if socketPath == "" {
		// No daemon socket configured — skip IPC check.
		return false, nil
	}

	dialer := &net.Dialer{Timeout: daemonIPCTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   daemonIPCTimeout,
	}

	url := fmt.Sprintf("http://keylatchd/v1/llm-session?pid=%s", strconv.Itoa(pid))
	req, reqErr := http.NewRequest(http.MethodGet, url, nil)
	if reqErr != nil {
		// Fail closed.
		return true, nil
	}

	resp, doErr := client.Do(req)
	if doErr != nil {
		// Network error or timeout → fail closed.
		return true, nil
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on read

	if resp.StatusCode != http.StatusOK {
		// Unexpected status → fail closed.
		return true, nil
	}

	var body LLMSessionResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr != nil {
		// Parse error → fail closed.
		return true, nil
	}

	if body.Schema != "v1" {
		// Unknown schema version → fail closed.
		return true, nil
	}

	return body.Active, nil
}

// currentPID returns the current process ID. Extracted for testability.
var currentPID = func() int { return os.Getpid() }
