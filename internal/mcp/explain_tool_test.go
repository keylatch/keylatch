package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func callExplain(t *testing.T, f ExplainFunc, args map[string]any) (string, bool) {
	t.Helper()
	result, err := makeExplainHandler(f)(context.Background(), buildRunRequest(t, args))
	require.NoError(t, err)
	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), result.IsError
}

func TestExplainToolPassesTheRunToTheExplainer(t *testing.T) {
	var got ExplainRequest
	text, isErr := callExplain(t, func(_ context.Context, req ExplainRequest) (any, error) {
		got = req
		return map[string]string{"decision": "allow"}, nil
	}, map[string]any{
		"provider": "openrouter", "account": "dev",
		"command": []any{"curl", "https://example.com"}, "cwd": "/work", "tier": "D2",
	})
	require.False(t, isErr, text)
	assert.JSONEq(t, `{"decision":"allow"}`, text)
	assert.Equal(t, ExplainRequest{Connection: "openrouter:dev", Command: []string{"curl", "https://example.com"}, CWD: "/work", Tier: "D2"}, got)
}

func TestExplainToolAcceptsACommandString(t *testing.T) {
	var got ExplainRequest
	_, isErr := callExplain(t, func(_ context.Context, req ExplainRequest) (any, error) {
		got = req
		return struct{}{}, nil
	}, map[string]any{"provider": "p", "command": "node script.js"})
	require.False(t, isErr)
	assert.Equal(t, "p", got.Connection)
	assert.Equal(t, []string{"node", "script.js"}, got.Command)
}

func TestExplainToolRefusals(t *testing.T) {
	ok := func(context.Context, ExplainRequest) (any, error) { return struct{}{}, nil }
	for name, tc := range map[string]struct {
		f    ExplainFunc
		args map[string]any
		want string
	}{
		"no provider":      {ok, map[string]any{"command": []any{"x"}}, "'provider' argument required"},
		"no command":       {ok, map[string]any{"provider": "p"}, "'command' argument required"},
		"invalid argument": {ok, map[string]any{"provider": "p", "command": []any{"echo", 42}}, "every command argument must be a string"},
		"no explainer": {nil, map[string]any{"provider": "p", "command": []any{"x"}},
			"no policy is configured"},
		"explainer error": {func(context.Context, ExplainRequest) (any, error) { return nil, errors.New("policy unreadable") },
			map[string]any{"provider": "p", "command": []any{"x"}}, "policy unreadable"},
		"unmarshalable": {func(context.Context, ExplainRequest) (any, error) { return make(chan int), nil },
			map[string]any{"provider": "p", "command": []any{"x"}}, "marshal error"},
	} {
		t.Run(name, func(t *testing.T) {
			text, isErr := callExplain(t, tc.f, tc.args)
			assert.True(t, isErr)
			assert.Contains(t, text, tc.want)
		})
	}
}
