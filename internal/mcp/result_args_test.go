package mcp

import (
	"encoding/json"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// result.go
// ---------------------------------------------------------------------------

func TestNewToolResultError(t *testing.T) {
	r := newToolResultError("something went wrong")
	require.NotNil(t, r)
	assert.True(t, r.IsError)
	require.Len(t, r.Content, 1)
	tc, ok := r.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "something went wrong", tc.Text)
}

func TestNewToolResultErrorf(t *testing.T) {
	r := newToolResultErrorf("error %d: %s", 42, "oops")
	require.NotNil(t, r)
	assert.True(t, r.IsError)
	require.Len(t, r.Content, 1)
	tc, ok := r.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "error 42: oops", tc.Text)
}

func TestNewTextContent(t *testing.T) {
	c := newTextContent("hello world")
	require.NotNil(t, c)
	tc, ok := c.(*sdkmcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "hello world", tc.Text)
}

func TestNewToolResultText(t *testing.T) {
	r := newToolResultText("ok")
	require.NotNil(t, r)
	assert.False(t, r.IsError)
	require.Len(t, r.Content, 1)
	tc, ok := r.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "ok", tc.Text)
}

// ---------------------------------------------------------------------------
// args.go
// ---------------------------------------------------------------------------

func TestGetArgumentsNilParams(t *testing.T) {
	req := &sdkmcp.CallToolRequest{Params: nil}
	args := getArguments(req)
	assert.NotNil(t, args)
	assert.Empty(t, args)
}

func TestGetArgumentsNilArguments(t *testing.T) {
	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{Arguments: nil},
	}
	args := getArguments(req)
	assert.NotNil(t, args)
	assert.Empty(t, args)
}

func TestGetArgumentsInvalidJSON(t *testing.T) {
	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{invalid json`),
		},
	}
	args := getArguments(req)
	assert.NotNil(t, args)
	assert.Empty(t, args)
}

func TestGetArgumentsValidJSON(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"key": "value", "num": float64(42)})
	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{Arguments: raw},
	}
	args := getArguments(req)
	assert.Equal(t, "value", args["key"])
	assert.Equal(t, float64(42), args["num"])
}

func TestGetStringMissingKey(t *testing.T) {
	args := map[string]any{"other": "val"}
	assert.Equal(t, "default", getString(args, "missing", "default"))
}

func TestGetStringNonStringValue(t *testing.T) {
	args := map[string]any{"num": 123}
	assert.Equal(t, "fallback", getString(args, "num", "fallback"))
}

func TestGetStringPresent(t *testing.T) {
	args := map[string]any{"provider": "openrouter"}
	assert.Equal(t, "openrouter", getString(args, "provider", ""))
}
