package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildRunRequest builds a CallToolRequest from an args map.
func buildRunRequest(t *testing.T, args map[string]any) *sdkmcp.CallToolRequest {
	t.Helper()
	var rawArgs json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		require.NoError(t, err)
		rawArgs = b
	}
	return &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{Arguments: rawArgs},
	}
}

// callRunHandler invokes makeRunHandler and returns text + isError.
func callRunHandler(t *testing.T, store *mockStore, d runner.Dispatcher, args map[string]any) (string, bool) {
	t.Helper()
	handler := makeRunHandler(store, d)
	result, err := handler(context.Background(), buildRunRequest(t, args))
	require.NoError(t, err, "handler must not return a Go error")

	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), result.IsError
}

// stubDispatcher records the request it is given and answers with a canned
// receipt, output and error.
type stubDispatcher struct {
	mu      sync.Mutex
	calls   int
	req     runner.ExecRequest
	receipt runner.RuntimeReceipt
	stdout  string
	stderr  string
	err     error
}

func (s *stubDispatcher) Run(_ context.Context, req runner.ExecRequest) (runner.RuntimeReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.req = req
	_, _ = io.WriteString(req.Stdout, s.stdout)
	_, _ = io.WriteString(req.Stderr, s.stderr)
	return s.receipt, s.err
}

// shellProvider registers a provider that allows the shell with these
// argument patterns and returns its slug and the shell's path.
func shellProvider(t *testing.T, slug string, entries ...string) (string, string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	require.NoError(t, registry.Register(registry.ConnectionTemplate{
		Provider:               slug,
		DisplayName:            "MCP run test " + slug,
		Category:               "test",
		AuthFlow:               "api_key",
		StoragePathTpl:         "default/test/" + slug + "/default",
		TrustLevel:             registry.TrustLocalOnly,
		SecretFields:           []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		AllowedCommandPrefixes: entries,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		Redaction:    []registry.RedactionRule{{Pattern: `leak-[0-9]+`, Replacement: "****"}},
		TestStrategy: registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
	}))
	return slug, sh
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

func TestRunHandlerMissingProvider(t *testing.T) {
	d := &stubDispatcher{}
	_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{})
	assert.True(t, isErr, "missing provider must produce an error result")
	assert.Zero(t, d.calls)
}

func TestRunHandlerUnknownProvider(t *testing.T) {
	d := &stubDispatcher{}
	_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": "nonexistent-provider-xyz-12345",
		"command":  []interface{}{"/bin/echo", "hello"},
	})
	assert.True(t, isErr, "unknown provider must produce an error result")
	assert.Zero(t, d.calls)
}

func TestRunHandlerMissingCommandKey(t *testing.T) {
	provider, _ := shellProvider(t, "mcp-run-nocmd", "sh ")
	d := &stubDispatcher{}
	_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider})
	assert.True(t, isErr, "missing command must produce an error result")
	assert.Zero(t, d.calls)
}

func TestRunRefusesWithoutADispatcher(t *testing.T) {
	provider, _ := shellProvider(t, "mcp-run-nodispatch", "sh ")
	text, isErr := callRunHandler(t, newMockStore(), nil, map[string]any{"provider": provider, "command": []interface{}{"sh", "-c", "true"}})
	assert.True(t, isErr)
	assert.Contains(t, text, "no runtime")
}

// ---------------------------------------------------------------------------
// The allowlist matches the executable exactly, never by string prefix.
// ---------------------------------------------------------------------------

func TestMCPExactAllowlist(t *testing.T) {
	provider, sh := shellProvider(t, "mcp-run-exact", "sh -c", "sh scripts/")
	for name, cmd := range map[string]any{
		"prefix of another binary":           []interface{}{"shell", "-c", "true"},
		"leading space":                      "  bash -c env",
		"other executable":                   []interface{}{"bash", "-c", "env"},
		"sibling name":                       []interface{}{sh + "evil", "-c", "true"},
		"argument pattern not met":           []interface{}{"sh", "-s"},
		"scripts escape":                     []interface{}{"sh", "scripts/../evil.sh"},
		"string form, name is a prefix":      "shx -c true",
		"allowed name with a path elsewhere": []interface{}{filepath.Join(t.TempDir(), "sh"), "-c", "true"},
	} {
		t.Run(name, func(t *testing.T) {
			d := &stubDispatcher{}
			_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider, "command": cmd})
			assert.True(t, isErr, "%v must be refused", cmd)
			assert.Zero(t, d.calls, "a refused command must never reach the dispatcher")
		})
	}

	for name, cmd := range map[string]any{
		"slice form":  []interface{}{"sh", "-c", "true"},
		"string form": "sh -c true",
		"directory":   []interface{}{"sh", "scripts/ok.sh"},
	} {
		t.Run("allowed/"+name, func(t *testing.T) {
			d := &stubDispatcher{}
			_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider, "command": cmd})
			assert.False(t, isErr)
			assert.Equal(t, 1, d.calls)
			assert.True(t, filepath.IsAbs(d.req.Command[0]), "the dispatcher gets the resolved executable, got %q", d.req.Command[0])
		})
	}
}

// ---------------------------------------------------------------------------
// The run is a dispatcher request from an agent caller; refusals and results
// come back as the dispatcher decided them.
// ---------------------------------------------------------------------------

func TestMCPRunUsesEnforce(t *testing.T) {
	provider, _ := shellProvider(t, "mcp-run-dispatch", "sh ")
	d := &stubDispatcher{
		receipt: runner.RuntimeReceipt{Runtime: "gateway_typed", ExitCode: 3},
		stdout:  "out leak-12345",
		stderr:  "err",
	}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": provider, "account": "myaccount", "namespace": "prod",
		"command": []interface{}{"sh", "-c", "true"},
	})
	require.False(t, isErr, text)

	assert.Equal(t, provider, d.req.ConnectionSlug)
	assert.Equal(t, callerkind.Agent, d.req.Caller)
	assert.Equal(t, "inject", d.req.Capability)
	assert.Equal(t, []string{d.req.Command[0]}, d.req.ExtraAllowedPrefixes)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt := result["receipt"].(map[string]any)
	assert.Equal(t, "gateway_typed", receipt["runtime"])
	assert.Equal(t, float64(3), receipt["exit_code"])
	assert.Equal(t, "prod/"+provider+"/myaccount", receipt["connection"])
	assert.Equal(t, "out ****", result["stdout"], "template redaction applies to the output")

	for runErr, want := range map[error]string{
		runner.ErrCommandNotAllowed:   "not allowed",
		runner.ErrGuardDenied:         "session guard",
		runner.ErrGatewayNotRunning:   "gateway is not running",
		audit.ErrUnavailable:          "audit log",
		errors.New("boom secret-123"): "execution error",
	} {
		denied := &stubDispatcher{err: runErr}
		text, isErr := callRunHandler(t, newMockStore(), denied, map[string]any{
			"provider": provider, "command": []interface{}{"sh", "-c", "true"},
		})
		assert.True(t, isErr)
		assert.Contains(t, text, want)
		assert.NotContains(t, text, "secret-123", "an error's text never reaches the caller")
	}
}

// ---------------------------------------------------------------------------
// End to end through the real DispatchRunner and the gateway_typed driver.
// ---------------------------------------------------------------------------

type fakeGateway struct{}

func (fakeGateway) Addr() string  { return "127.0.0.1:7878" }
func (fakeGateway) Running() bool { return true }

type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func realDispatcher(t *testing.T, em audit.Emitter) runner.DispatchRunner {
	t.Helper()
	return runner.DispatchRunner{
		Audit: em,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeGatewayTyped): runner.NewGatewayTypedDriver(fakeGateway{}, make([]byte, 32), filepath.Join(t.TempDir(), "tokens.json")),
		},
	}
}

// A permitted run goes through the gateway_typed runtime with exactly one
// audit event, and the child sees no backend credential.
func TestMCPRunAudited(t *testing.T) {
	provider, sh := shellProvider(t, "mcp-run-audited", "sh ")
	em := &recordingEmitter{}
	text, isErr := callRunHandler(t, newMockStore(), realDispatcher(t, em), map[string]any{
		"provider": provider,
		"command":  []interface{}{sh, "-c", "echo ran"},
	})
	require.False(t, isErr, text)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	assert.Equal(t, "gateway_typed", result["receipt"].(map[string]any)["runtime"])
	assert.Contains(t, result["stdout"], "ran")

	require.Len(t, em.events, 1, "one audit event per run")
	ev := em.events[0]
	assert.Equal(t, audit.ActionRun, ev.Action)
	assert.Equal(t, "agent", ev.Extra["caller_kind"])
	assert.Equal(t, "gateway_typed", ev.Extra["runtime"])
	assert.Equal(t, provider, ev.Extra["connection"])
}

// The child's environment is scrubbed of backend credentials and Keylatch
// configuration, whatever the MCP server's own environment holds.
func TestMCPChildEnvScrubbed(t *testing.T) {
	provider, sh := shellProvider(t, "mcp-run-env", "sh ")
	t.Setenv("BW_SESSION", "audit-synthetic-session-9284")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "audit-synthetic-sa-1111")
	t.Setenv("VAULT_TOKEN", "audit-synthetic-vault-2222")
	t.Setenv("KEYLATCH_BACKEND", "audit-synthetic-backend")

	body, isErr := callRunHandler(t, newMockStore(), realDispatcher(t, &recordingEmitter{}), map[string]any{
		"provider": provider,
		"command":  []interface{}{sh, "-c", "env"},
	})
	require.False(t, isErr, body)
	for _, leaked := range []string{"audit-synthetic-session-9284", "audit-synthetic-sa-1111", "audit-synthetic-vault-2222", "audit-synthetic-backend"} {
		assert.NotContains(t, body, leaked)
	}
}
