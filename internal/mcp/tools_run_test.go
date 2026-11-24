package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeDispatcher records the ExecRequest it receives and writes canned output
// to the request's writers.
type fakeDispatcher struct {
	stdout   string
	stderr   string
	exitCode int
	err      error

	calls int
	got   runner.ExecRequest
}

func (f *fakeDispatcher) Run(_ context.Context, req runner.ExecRequest) (runner.RuntimeReceipt, error) {
	f.calls++
	f.got = req
	if f.err != nil {
		return runner.RuntimeReceipt{Provider: req.ConnectionSlug}, f.err
	}
	if req.Stdout != nil {
		_, _ = req.Stdout.Write([]byte(f.stdout))
	}
	if req.Stderr != nil {
		_, _ = req.Stderr.Write([]byte(f.stderr))
	}
	return runner.RuntimeReceipt{Provider: req.ConnectionSlug, Runtime: req.Runtime, ExitCode: f.exitCode}, nil
}

// runTestProvider is a registered template whose allowlist accepts absolute paths.
const runTestProvider = "mcp-run-test"

func registerRunTestTemplate(t *testing.T) {
	t.Helper()
	// Duplicate registration across tests is expected and harmless.
	_ = registry.Register(registry.ConnectionTemplate{
		Provider:               runTestProvider,
		DisplayName:            "MCP Run Test",
		Category:               "test",
		AuthFlow:               "api_key",
		StoragePathTpl:         "default/test/" + runTestProvider + "/default",
		TrustLevel:             registry.TrustLocalOnly,
		SecretFields:           []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		AllowedCommandPrefixes: []string{"/opt/tool "},
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		TestStrategy: registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
	})
}

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
	ctx := context.Background()
	handler := makeRunHandler(store, d)
	req := buildRunRequest(t, args)
	result, err := handler(ctx, req)
	require.NoError(t, err, "handler must not return a Go error")

	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), result.IsError
}

// ---------------------------------------------------------------------------
// makeRunHandler: missing provider
// ---------------------------------------------------------------------------

func TestRunHandlerMissingProvider(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	_, isErr := callRunHandler(t, store, d, map[string]any{})
	assert.True(t, isErr, "missing provider must produce an error result")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: provider not found in registry
// ---------------------------------------------------------------------------

func TestRunHandlerUnknownProvider(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	_, isErr := callRunHandler(t, store, d, map[string]any{
		"provider": "nonexistent-provider-xyz-12345",
		"command":  []interface{}{"/bin/echo", "hello"},
	})
	assert.True(t, isErr, "unknown provider must produce an error result")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: command rejected by allowlist (string form)
// ---------------------------------------------------------------------------

func TestRunHandlerCommandRejectedByAllowlistStringForm(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	// "sentry" has AllowedCommandPrefixes ["node ", "python3 "]; "bash" is not allowed.
	_, isErr := callRunHandler(t, store, d, map[string]any{
		"provider": "sentry",
		"command":  "bash -c env",
	})
	assert.True(t, isErr, "banned command (string form) must produce an error result")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: command rejected by allowlist ([]interface{} form)
// ---------------------------------------------------------------------------

func TestRunHandlerCommandRejectedByAllowlistSliceForm(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	// "bash" doesn't match "node " or "python3 " prefixes.
	_, isErr := callRunHandler(t, store, d, map[string]any{
		"provider": "sentry",
		"command":  []interface{}{"bash", "-c", "env"},
	})
	assert.True(t, isErr, "banned command (slice form) must produce an error result")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: missing command key (hits empty-command guard)
// ---------------------------------------------------------------------------

func TestRunHandlerMissingCommandKey(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	// No "command" key — args["command"] is nil, hits default case in type switch,
	// command stays nil, len(command)==0 → "run: 'command' argument required".
	_, isErr := callRunHandler(t, store, d, map[string]any{
		"provider": "sentry",
	})
	assert.True(t, isErr, "missing command must produce an error result")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: relative command rejected
// ---------------------------------------------------------------------------

func TestRunHandlerRejectsRelativeCommand(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{}
	// "sentry" allows "node "; the command passes the allowlist but is not absolute.
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": "sentry",
		"command":  "node script.js",
	})
	assert.True(t, isErr)
	assert.Contains(t, text, "absolute path")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: nil dispatcher
// ---------------------------------------------------------------------------

func TestRunHandlerNilDispatcher(t *testing.T) {
	registerRunTestTemplate(t)
	text, isErr := callRunHandler(t, newMockStore(), nil, map[string]any{
		"provider": runTestProvider,
		"command":  "/opt/tool script.js",
	})
	assert.True(t, isErr, "nil dispatcher must produce an error result")
	assert.Contains(t, text, "runtime dispatch unavailable")
}

// ---------------------------------------------------------------------------
// makeRunHandler: provider without runtime support
// ---------------------------------------------------------------------------

func TestRunHandlerProviderWithoutRuntimeSupport(t *testing.T) {
	_ = registry.Register(registry.ConnectionTemplate{
		Provider:               "mcp-run-no-runtime",
		DisplayName:            "MCP Run No Runtime",
		Category:               "test",
		AuthFlow:               "api_key",
		StoragePathTpl:         "default/test/mcp-run-no-runtime/default",
		TrustLevel:             registry.TrustLocalOnly,
		SecretFields:           []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		AllowedCommandPrefixes: []string{"/opt/tool "},
		TestStrategy:           registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
	})
	d := &fakeDispatcher{}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": "mcp-run-no-runtime",
		"command":  "/opt/tool script.js",
	})
	assert.True(t, isErr)
	assert.Contains(t, text, "no supported runtime")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: dispatch error
// ---------------------------------------------------------------------------

func TestRunHandlerDispatchError(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stdout: "must not appear", err: errors.New("gateway is not running")}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": runTestProvider,
		"command":  "/opt/tool script.js",
	})
	assert.True(t, isErr, "dispatch error must produce an error result")
	assert.Contains(t, text, "gateway is not running")
	assert.NotContains(t, text, "must not appear")
	assert.Equal(t, 1, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: successful execution (string command)
// ---------------------------------------------------------------------------

func TestRunHandlerSuccessStringCommand(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stdout: "hello output"}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": runTestProvider,
		"command":  "/opt/tool script.js",
	})
	assert.False(t, isErr, "valid command must not be an error result")
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	assert.Contains(t, result, "receipt")
	assert.Equal(t, "hello output", result["stdout"])

	assert.Equal(t, []string{"/opt/tool", "script.js"}, d.got.Command)
	assert.Equal(t, runTestProvider, d.got.ConnectionSlug)
	assert.Equal(t, "mcp", d.got.Actor)
	assert.Equal(t, string(registry.RuntimeGatewayTyped), d.got.Runtime)
	assert.NotNil(t, d.got.Stdin)
	assert.NotNil(t, d.got.Stdout)
	assert.NotNil(t, d.got.Stderr)
}

// ---------------------------------------------------------------------------
// makeRunHandler: successful execution ([]interface{} command)
// ---------------------------------------------------------------------------

func TestRunHandlerSuccessSliceCommand(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stdout: "slice output"}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": runTestProvider,
		"command":  []interface{}{"/opt/tool", "script.js"},
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	assert.Contains(t, result, "receipt")
}

// ---------------------------------------------------------------------------
// makeRunHandler: receipt contains expected fields
// ---------------------------------------------------------------------------

func TestRunHandlerReceiptFields(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stdout: "output"}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider":  runTestProvider,
		"account":   "myaccount",
		"namespace": "prod",
		"command":   "/opt/tool script.js",
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt, ok := result["receipt"].(map[string]interface{})
	require.True(t, ok, "receipt must be an object")
	assert.Equal(t, runTestProvider, receipt["provider"])
	assert.Contains(t, receipt["connection"], "myaccount")
	assert.Equal(t, string(registry.RuntimeGatewayTyped), receipt["runtime"])
}

// ---------------------------------------------------------------------------
// makeRunHandler: non-zero exit code recorded in receipt
// ---------------------------------------------------------------------------

func TestRunHandlerNonZeroExitCode(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stderr: "error output", exitCode: 1}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": runTestProvider,
		"command":  "/opt/tool script.js",
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt := result["receipt"].(map[string]interface{})
	assert.Equal(t, float64(1), receipt["exit_code"])
	assert.Equal(t, "error output", result["stderr"])
}

// ---------------------------------------------------------------------------
// makeRunHandler: leading space bypass prevention
// ---------------------------------------------------------------------------

func TestRunHandlerLeadingSpaceBypass(t *testing.T) {
	store := newMockStore()
	d := &fakeDispatcher{}
	// "  bash -c env" trimmed to "bash -c env" which doesn't match "node " or "python3 ".
	_, isErr := callRunHandler(t, store, d, map[string]any{
		"provider": "sentry",
		"command":  "  bash -c env",
	})
	assert.True(t, isErr, "leading-space bypass must be rejected")
	assert.Zero(t, d.calls)
}

// ---------------------------------------------------------------------------
// makeRunHandler: default account and namespace
// ---------------------------------------------------------------------------

func TestRunHandlerDefaultsAccountNamespace(t *testing.T) {
	registerRunTestTemplate(t)
	d := &fakeDispatcher{stdout: "ok"}
	text, isErr := callRunHandler(t, newMockStore(), d, map[string]any{
		"provider": runTestProvider,
		"command":  "/opt/tool script.js",
		// no account, no namespace — defaults to "default"
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt := result["receipt"].(map[string]interface{})
	assert.Equal(t, "default/"+runTestProvider+"/default", receipt["connection"])
}

// ---------------------------------------------------------------------------
// applyRedaction
// ---------------------------------------------------------------------------

func TestApplyRedactionNoRules(t *testing.T) {
	result := applyRedaction("secret token here", nil)
	assert.Equal(t, "secret token here", result)
}

func TestApplyRedactionMatchesPattern(t *testing.T) {
	rules := []registry.RedactionRule{
		{Pattern: `sntrys_[A-Za-z0-9\-_]{32,}`, Replacement: "****"},
	}
	input := "auth: sntrys_abcdefghijklmnopqrstuvwxyz1234567890"
	result := applyRedaction(input, rules)
	assert.NotContains(t, result, "sntrys_")
	assert.Contains(t, result, "****")
}

func TestApplyRedactionInvalidPatternSkipped(t *testing.T) {
	rules := []registry.RedactionRule{
		{Pattern: `[invalid(`, Replacement: "****"},
	}
	input := "unchanged text"
	result := applyRedaction(input, rules)
	assert.Equal(t, "unchanged text", result)
}

func TestApplyRedactionMultipleRules(t *testing.T) {
	rules := []registry.RedactionRule{
		{Pattern: `TOKEN_[A-Z]+`, Replacement: "<token>"},
		{Pattern: `SECRET_[0-9]+`, Replacement: "<secret>"},
	}
	input := "TOKEN_ABC and SECRET_123"
	result := applyRedaction(input, rules)
	assert.Equal(t, "<token> and <secret>", result)
}

// ---------------------------------------------------------------------------
// sanitizeError
// ---------------------------------------------------------------------------

func TestSanitizeErrorNil(t *testing.T) {
	assert.Equal(t, "", sanitizeError(nil))
}

func TestSanitizeErrorPlainMessage(t *testing.T) {
	err := errors.New("connection refused")
	result := sanitizeError(err)
	assert.Equal(t, "connection refused", result)
}

func TestSanitizeErrorRedactsTokenShapedStrings(t *testing.T) {
	// 32+ base64url chars get redacted
	longToken := "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
	err := errors.New("invalid token: " + longToken)
	result := sanitizeError(err)
	assert.NotContains(t, result, longToken)
	assert.Contains(t, result, "****")
}

func TestSanitizeErrorPreservesShortStrings(t *testing.T) {
	err := errors.New("short err")
	result := sanitizeError(err)
	assert.Equal(t, "short err", result)
}
