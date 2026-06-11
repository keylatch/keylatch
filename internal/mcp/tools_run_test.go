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

	"github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/registry"
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
func callRunHandler(t *testing.T, store *mockStore, runner exec.CommandRunner, args map[string]any) (string, bool) {
	t.Helper()
	ctx := context.Background()
	handler := makeRunHandler(store, runner)
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
	runner := &exec.MockRunner{}
	_, isErr := callRunHandler(t, store, runner, map[string]any{})
	assert.True(t, isErr, "missing provider must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: provider not found in registry
// ---------------------------------------------------------------------------

func TestRunHandlerUnknownProvider(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{}
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "nonexistent-provider-xyz-12345",
		"command":  []interface{}{"/bin/echo", "hello"},
	})
	assert.True(t, isErr, "unknown provider must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: command rejected by allowlist (string form)
// ---------------------------------------------------------------------------

func TestRunHandlerCommandRejectedByAllowlistStringForm(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{}
	// "sentry" has AllowedCommandPrefixes ["node ", "python3 "]; "bash" is not allowed.
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "bash -c env",
	})
	assert.True(t, isErr, "banned command (string form) must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: command rejected by allowlist ([]interface{} form)
// ---------------------------------------------------------------------------

func TestRunHandlerCommandRejectedByAllowlistSliceForm(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{}
	// "bash" doesn't match "node " or "python3 " prefixes.
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  []interface{}{"bash", "-c", "env"},
	})
	assert.True(t, isErr, "banned command (slice form) must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: missing command key (hits empty-command guard)
// ---------------------------------------------------------------------------

func TestRunHandlerMissingCommandKey(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{}
	// No "command" key — args["command"] is nil, hits default case in type switch,
	// command stays nil, len(command)==0 → "run: 'command' argument required".
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
	})
	assert.True(t, isErr, "missing command must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: execution error from runner
// ---------------------------------------------------------------------------

func TestRunHandlerExecutionError(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {
				Err: errors.New("exec: binary not found"),
			},
		},
	}
	// "sentry" allows "node "; command starts with "node ".
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "node script.js",
	})
	assert.True(t, isErr, "runner error must produce an error result")
}

// ---------------------------------------------------------------------------
// makeRunHandler: successful execution (string command)
// ---------------------------------------------------------------------------

func TestRunHandlerSuccessStringCommand(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {
				Stdout:   []byte("hello output"),
				ExitCode: 0,
			},
		},
	}
	text, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "node script.js",
	})
	assert.False(t, isErr, "valid command must not be an error result")
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	assert.Contains(t, result, "receipt")
	assert.Contains(t, result, "stdout")
}

// ---------------------------------------------------------------------------
// makeRunHandler: successful execution ([]interface{} command)
// ---------------------------------------------------------------------------

func TestRunHandlerSuccessSliceCommand(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {
				Stdout:   []byte("slice output"),
				ExitCode: 0,
			},
		},
	}
	text, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  []interface{}{"node", "script.js"},
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
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {Stdout: []byte("output"), ExitCode: 0},
		},
	}
	text, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider":  "sentry",
		"account":   "myaccount",
		"namespace": "prod",
		"command":   "node script.js",
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt, ok := result["receipt"].(map[string]interface{})
	require.True(t, ok, "receipt must be an object")
	assert.Equal(t, "sentry", receipt["provider"])
	assert.Contains(t, receipt["connection"], "myaccount")
}

// ---------------------------------------------------------------------------
// makeRunHandler: non-zero exit code recorded in receipt
// ---------------------------------------------------------------------------

func TestRunHandlerNonZeroExitCode(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {
				Stderr:   []byte("error output"),
				ExitCode: 1,
			},
		},
	}
	text, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "node script.js",
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt := result["receipt"].(map[string]interface{})
	assert.Equal(t, float64(1), receipt["exit_code"])
}

// ---------------------------------------------------------------------------
// makeRunHandler: leading space bypass prevention (FIND-004)
// ---------------------------------------------------------------------------

func TestRunHandlerLeadingSpaceBypass(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{}
	// "  bash -c env" trimmed to "bash -c env" which doesn't match "node " or "python3 ".
	_, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "  bash -c env",
	})
	assert.True(t, isErr, "leading-space bypass must be rejected")
}

// ---------------------------------------------------------------------------
// makeRunHandler: default account and namespace
// ---------------------------------------------------------------------------

func TestRunHandlerDefaultsAccountNamespace(t *testing.T) {
	store := newMockStore()
	runner := &exec.MockRunner{
		Responses: map[string]exec.MockResponse{
			"node|script.js": {Stdout: []byte("ok"), ExitCode: 0},
		},
	}
	text, isErr := callRunHandler(t, store, runner, map[string]any{
		"provider": "sentry",
		"command":  "node script.js",
		// no account, no namespace — defaults to "default"
	})
	assert.False(t, isErr)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	receipt := result["receipt"].(map[string]interface{})
	assert.Equal(t, "default/sentry/default", receipt["connection"])
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
