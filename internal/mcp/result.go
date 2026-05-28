package mcp

import (
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// newToolResultText returns a successful *CallToolResult wrapping a plain text string.
// Mirrors mark3labs's mcpgo.NewToolResultText(s).
func newToolResultText(text string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: text}},
	}
}

// newToolResultError returns an IsError=true *CallToolResult with the given message.
// Mirrors mark3labs's mcpgo.NewToolResultError(msg).
func newToolResultError(msg string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		IsError: true,
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: msg}},
	}
}

// newToolResultErrorf is the printf-style variant of newToolResultError.
// Mirrors mark3labs's mcpgo.NewToolResultErrorf(format, args...).
func newToolResultErrorf(format string, args ...any) *sdkmcp.CallToolResult {
	return newToolResultError(fmt.Sprintf(format, args...))
}

// newTextContent wraps a string in a *TextContent Content value.
// Mirrors mark3labs's mcpgo.NewTextContent(s).
//
//nolint:unused // planned: used by MCP tool handlers in Phase 12 when JSON result types are unified
func newTextContent(text string) sdkmcp.Content {
	return &sdkmcp.TextContent{Text: text}
}
