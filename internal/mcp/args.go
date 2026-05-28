package mcp

import (
	"encoding/json"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// getArguments extracts the arguments map from an SDK CallToolRequest.
// Returns an empty (non-nil) map when arguments are absent or unparseable.
// Mirrors mark3labs's req.GetArguments() semantics.
func getArguments(req *sdkmcp.CallToolRequest) map[string]any {
	if req.Params == nil || req.Params.Arguments == nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &m); err != nil {
		return map[string]any{}
	}
	return m
}

// getString extracts a named string argument from the args map, returning def
// if the key is absent or the value is not a string.
// Mirrors mark3labs's req.GetString(name, default) semantics.
func getString(args map[string]any, name, def string) string {
	v, ok := args[name]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}
