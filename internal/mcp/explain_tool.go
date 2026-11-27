package mcp

import (
	"context"
	"encoding/json"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ExplainRequest is the run keylatch_explain is asked about.
type ExplainRequest struct {
	Connection string
	Command    []string
	CWD        string
	Tier       string
}

// ExplainFunc evaluates a run against policy without executing it and returns
// a JSON-serializable report. It must not read secret values.
type ExplainFunc func(ctx context.Context, req ExplainRequest) (any, error)

// makeExplainHandler implements keylatch_explain. The connection is named like
// keylatch_run names it: the provider, with an optional account suffix.
func makeExplainHandler(explainer ExplainFunc) sdkmcp.ToolHandler {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
		args := getArguments(req)
		provider := getString(args, "provider", "")
		if provider == "" {
			return newToolResultError("explain: 'provider' argument required"), nil
		}
		var command []string
		switch v := args["command"].(type) {
		case []interface{}:
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return newToolResultError("explain: every command argument must be a string"), nil
				}
				command = append(command, s)
			}
		case string:
			command = strings.Fields(v)
		}
		if len(command) == 0 {
			return newToolResultError("explain: 'command' argument required"), nil
		}
		if explainer == nil {
			return newToolResultError("explain: no policy is configured for this server"), nil
		}
		connection := provider
		if account := getString(args, "account", ""); account != "" {
			connection += ":" + account
		}
		report, err := explainer(ctx, ExplainRequest{
			Connection: connection,
			Command:    command,
			CWD:        getString(args, "cwd", ""),
			Tier:       getString(args, "tier", ""),
		})
		if err != nil {
			return newToolResultErrorf("explain: %s", sanitizeError(err)), nil
		}
		data, err := json.Marshal(report)
		if err != nil {
			return newToolResultError("internal: marshal error"), nil
		}
		return newToolResultText(string(data)), nil
	}
}
