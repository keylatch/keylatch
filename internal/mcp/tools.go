package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/registry"
)

// registeredTools is the canonical list of tool names.
// Must have exactly five entries.
var registeredTools = []string{
	"keylatch_status",
	"keylatch_list_connections",
	"keylatch_describe",
	"keylatch_test",
	"keylatch_run",
}

func init() {
	// Compile-time assertion that exactly five tools are registered.
	const assertFiveTools = 5
	if len(registeredTools) != assertFiveTools {
		panic(fmt.Sprintf("mcp: exactly five tools required; got %d", len(registeredTools)))
	}
}

// testCallRateLimiter tracks the last call time per connection for keylatch_test.
// Rate limit: 1 call per connection per 30 seconds.
var testCallRateLimiter = &rateLimiter{
	calls:  make(map[string]time.Time),
	window: 30 * time.Second,
}

type rateLimiter struct {
	mu     sync.Mutex
	calls  map[string]time.Time
	window time.Duration
}

// Allow returns true if the call is within the rate limit.
func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.calls[key]
	if !ok || time.Since(last) >= r.window {
		r.calls[key] = time.Now()
		return true
	}
	return false
}

// objectSchema is the minimal JSON Schema required by Server.AddTool for tools
// that do not define formal property constraints.
var objectSchema = json.RawMessage(`{"type":"object"}`)

// tokenRedactRE matches token-shaped strings (32+ base64url chars) for redaction.
// Package-level to avoid recompiling on every sanitizeError call (Warning 4).
var tokenRedactRE = regexp.MustCompile(`[A-Za-z0-9\-_\.]{32,}`)

// RegisterTools adds all five tool handlers to the MCP Server.
func RegisterTools(s *sdkmcp.Server, store connections.Store, runner exec.CommandRunner) {
	if runner == nil {
		runner = exec.DefaultRunner
	}

	s.AddTool(
		&sdkmcp.Tool{
			Name:        "keylatch_status",
			Description: "List all connections with their health status. Returns no secret values.",
			InputSchema: objectSchema,
		},
		makeStatusHandler(store),
	)

	s.AddTool(
		&sdkmcp.Tool{
			Name:        "keylatch_list_connections",
			Description: "List provider/account/namespace/runtime for all connections. Returns field names only.",
			InputSchema: objectSchema,
		},
		makeListConnectionsHandler(store),
	)

	s.AddTool(
		&sdkmcp.Tool{
			Name:        "keylatch_describe",
			Description: "Describe a provider's connection template. Returns masked template with no secret values.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"}},"required":["provider"]}`),
		},
		makeDescribeHandler(store),
	)

	s.AddTool(
		&sdkmcp.Tool{
			Name:        "keylatch_test",
			Description: "Test a connection's health. Rate-limited to 1 call per connection per 30 seconds.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"account":{"type":"string"},"namespace":{"type":"string"}},"required":["provider"]}`),
		},
		makeTestHandler(store),
	)

	s.AddTool(
		&sdkmcp.Tool{
			Name:        "keylatch_run",
			Description: "Run a command using a connection's credentials. Command must match the provider's allowed_command_prefixes allowlist.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"provider":{"type":"string"},"account":{"type":"string"},"namespace":{"type":"string"},"command":{}},"required":["provider","command"]}`),
		},
		makeRunHandler(store, runner),
	)
}

// makeStatusHandler implements keylatch_status.
// Delegates to connections.Status; returns masked []ConnectionStatus; no secret fields.
func makeStatusHandler(store connections.Store) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		statuses, err := connections.Status(ctx, connections.StatusOptions{Namespace: "default"}, store)
		if err != nil {
			return newToolResultErrorf("status: %s", sanitizeError(err)), nil
		}
		data, err := json.Marshal(statuses)
		if err != nil {
			return newToolResultError("status: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}

// makeListConnectionsHandler implements keylatch_list_connections.
// Returns provider/account/namespace/runtime/fields-names-only.
func makeListConnectionsHandler(store connections.Store) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		statuses, err := connections.Status(ctx, connections.StatusOptions{Namespace: "default"}, store)
		if err != nil {
			return newToolResultErrorf("list_connections: %s", sanitizeError(err)), nil
		}
		type listEntry struct {
			Provider  string   `json:"provider"`
			Account   string   `json:"account"`
			Namespace string   `json:"namespace"`
			Runtime   string   `json:"runtime"`
			Fields    []string `json:"fields"` // names only
		}
		out := make([]listEntry, 0, len(statuses))
		for _, s := range statuses {
			out = append(out, listEntry{
				Provider:  s.Connection.Provider,
				Account:   s.Connection.Account,
				Namespace: s.Connection.Namespace,
				Runtime:   string(s.Connection.Runtime),
				Fields:    s.Connection.Fields,
			})
		}
		data, err := json.Marshal(out)
		if err != nil {
			return newToolResultError("internal: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}

// makeDescribeHandler implements keylatch_describe.
// Returns masked template + masked_fields map.
func makeDescribeHandler(store connections.Store) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		args := getArguments(req)
		provider := getString(args, "provider", "")
		if provider == "" {
			return newToolResultError("describe: 'provider' argument required"), nil
		}
		tmpl, masked, err := connections.Describe(ctx, provider, store)
		if err != nil {
			return newToolResultErrorf("describe: %s", sanitizeError(err)), nil
		}
		result := map[string]interface{}{
			"template":      tmpl,
			"masked_fields": masked,
		}
		data, err := json.Marshal(result)
		if err != nil {
			return newToolResultError("internal: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}

// makeTestHandler implements keylatch_test.
// Rate-limited to 1 call per connection per 30s.
func makeTestHandler(store connections.Store) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		args := getArguments(req)
		provider := getString(args, "provider", "")
		account := getString(args, "account", "")
		namespace := getString(args, "namespace", "")
		if provider == "" {
			return newToolResultError("test: 'provider' argument required"), nil
		}
		if namespace == "" {
			namespace = "default"
		}
		if account == "" {
			account = "default"
		}
		rateLimitKey := fmt.Sprintf("%s/%s/%s", namespace, provider, account)
		if !testCallRateLimiter.Allow(rateLimitKey) {
			return newToolResultError("test: rate limit exceeded; wait 30s between tests for the same connection"), nil
		}
		result, err := connections.Test(ctx, provider, account, namespace, store, &http.Client{Timeout: 10 * time.Second})
		if err != nil {
			return newToolResultErrorf("test: %s", sanitizeError(err)), nil
		}
		data, merr := json.Marshal(result)
		if merr != nil {
			return newToolResultError("internal: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}

// makeRunHandler implements keylatch_run.
// Applies allowlist pre-flight before execution.
func makeRunHandler(store connections.Store, runner exec.CommandRunner) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		args := getArguments(req)
		provider := getString(args, "provider", "")
		account := getString(args, "account", "")
		namespace := getString(args, "namespace", "")
		if provider == "" {
			return newToolResultError("run: 'provider' argument required"), nil
		}
		if namespace == "" {
			namespace = "default"
		}
		if account == "" {
			account = "default"
		}

		// Allowlist pre-flight — fetch template before parsing command.
		tmpl, err := registry.Get(provider)
		if err != nil {
			return newToolResultError("run: provider not found"), nil
		}

		// Parse command.
		var (
			command          []string
			allowlistChecked bool
		)
		switch v := args["command"].(type) {
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					command = append(command, s)
				}
			}
		case string:
			// Check the raw trimmed string to prevent leading-space bypass.
			// "  node exploit.js" must not pass a "node " prefix check.
			raw := strings.TrimSpace(v)
			command = strings.Fields(raw)
			if !commandMatchesAllowlist(raw, tmpl.AllowedCommandPrefixes) {
				return newToolResultError("run: command not in allowed_command_prefixes for this provider"), nil
			}
			allowlistChecked = true
		}
		if len(command) == 0 {
			return newToolResultError("run: 'command' argument required"), nil
		}

		// Allowlist pre-flight for the []interface{} path (not yet checked above).
		if !allowlistChecked {
			cmdLine := strings.Join(command, " ")
			if !commandMatchesAllowlist(cmdLine, tmpl.AllowedCommandPrefixes) {
				return newToolResultError("run: command not in allowed_command_prefixes for this provider"), nil
			}
		}

		// Resolve binary — must be an absolute path.
		binary := command[0]
		cmdArgs := command[1:]

		// Execute via runner.
		stdout, stderr, exitCode, execErr := runner.Run(ctx, binary, cmdArgs, nil)
		if execErr != nil {
			return newToolResultError("run: execution error"), nil
		}

		// Apply redaction patterns to stdout/stderr before returning.
		cleanedStdout := applyRedaction(string(stdout), tmpl.Redaction)
		cleanedStderr := applyRedaction(string(stderr), tmpl.Redaction)

		receipt := RuntimeReceipt{
			Provider:   provider,
			Connection: fmt.Sprintf("%s/%s/%s", namespace, provider, account), // HMAC'd in a future revision
			Runtime:    string(tmpl.RuntimeSupport.Preferred),
			ExitCode:   exitCode,
		}

		result := map[string]interface{}{
			"receipt": receipt,
			"stdout":  cleanedStdout,
			"stderr":  cleanedStderr,
		}
		data, merr := json.Marshal(result)
		if merr != nil {
			return newToolResultError("internal: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}

// commandMatchesAllowlist checks whether cmdLine starts with one of the allowed prefixes.
// Returns false if allowlist is empty (deny-all when no prefixes configured).
func commandMatchesAllowlist(cmdLine string, allowedPrefixes []string) bool {
	if len(allowedPrefixes) == 0 {
		return false
	}
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cmdLine, prefix) {
			return true
		}
	}
	return false
}

// applyRedaction applies all redaction patterns to text, replacing matches
// with their configured replacements.
func applyRedaction(text string, rules []registry.RedactionRule) string {
	for _, rule := range rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		text = re.ReplaceAllString(text, rule.Replacement)
	}
	return text
}

// sanitizeError converts an error to a safe string with no credential bytes.
func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	// Return only the error type name, not the full message, to avoid leaking
	// paths or secret-shaped strings in error text.
	msg := err.Error()
	// Strip anything that looks like a token using the package-level compiled RE.
	msg = tokenRedactRE.ReplaceAllString(msg, "****")
	return msg
}
