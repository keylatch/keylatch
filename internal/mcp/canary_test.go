package mcp

import (
	"context"
	"encoding/json"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryPhase3MCP = "KEYLATCH_CANARY_PHASE3_MCP_0xDEADBEEF"

// setupCanaryConnection seeds a fixture connection with a canary value in the vault.
func setupCanaryConnection(t *testing.T, store *mockStore) {
	t.Helper()
	ctx := context.Background()

	_, err := connections.Connect(ctx, "openrouter", connections.ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte(canaryPhase3MCP)},
	}, store)
	require.NoError(t, err)
}

// invokeHandler directly calls a tool handler function with the given arguments.
// The handler type is sdkmcp.ToolHandler (the official SDK's untyped handler).
func invokeHandler(t *testing.T, handler sdkmcp.ToolHandler, args map[string]any) string {
	t.Helper()
	ctx := context.Background()

	var rawArgs json.RawMessage
	if args != nil {
		var err error
		rawArgs, err = json.Marshal(args)
		require.NoError(t, err)
	}

	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Arguments: rawArgs,
		},
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)

	var sb []byte
	for _, c := range result.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb = append(sb, []byte(tc.Text)...)
		}
	}
	return string(sb)
}

// TestCanaryDoesNotLeakThroughMCPTools verifies that the canary value injected
// into a fixture connection does not appear in any tool response.
func TestCanaryDoesNotLeakThroughMCPTools(t *testing.T) {
	store := newMockStore()
	setupCanaryConnection(t, store)

	statusHandler := makeStatusHandler(store)
	listHandler := makeListConnectionsHandler(store)
	describeHandler := makeDescribeHandler(store)
	testHandler := makeTestHandler(store)

	toolCalls := []struct {
		name    string
		handler sdkmcp.ToolHandler
		args    map[string]any
	}{
		{"keylatch_status", statusHandler, nil},
		{"keylatch_list_connections", listHandler, nil},
		{"keylatch_describe", describeHandler, map[string]any{"provider": "openrouter"}},
		{"keylatch_test", testHandler, map[string]any{"provider": "openrouter"}},
	}

	for _, tc := range toolCalls {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			response := invokeHandler(t, tc.handler, tc.args)
			assert.NotContains(t, response, canaryPhase3MCP,
				"tool %q must not contain canary value in response", tc.name)
		})
	}
}

// TestStatusToolReturnsNoSecretFields verifies that keylatch_status returns
// only metadata, never secret field values.
func TestStatusToolReturnsNoSecretFields(t *testing.T) {
	store := newMockStore()
	setupCanaryConnection(t, store)

	statusHandler := makeStatusHandler(store)
	response := invokeHandler(t, statusHandler, nil)

	// The response is JSON — parse and verify no secret values appear.
	var statuses []connections.ConnectionStatus
	err := json.Unmarshal([]byte(response), &statuses)
	require.NoError(t, err)

	for _, s := range statuses {
		// Fields must contain field NAMES only.
		for _, f := range s.Connection.Fields {
			assert.NotEqual(t, canaryPhase3MCP, f,
				"connection field must be a name, not a value")
		}
	}
}

// TestDescribeToolReturnsMaskedFields verifies that keylatch_describe returns
// "****" for all secret fields (S3-10).
func TestDescribeToolReturnsMaskedFields(t *testing.T) {
	store := newMockStore()
	describeHandler := makeDescribeHandler(store)

	response := invokeHandler(t, describeHandler, map[string]any{"provider": "openrouter"})

	var result map[string]interface{}
	err := json.Unmarshal([]byte(response), &result)
	require.NoError(t, err)

	masked, ok := result["masked_fields"].(map[string]interface{})
	assert.True(t, ok, "describe must return masked_fields")
	for k, v := range masked {
		assert.Equal(t, "****", v, "masked field %q must have value ****", k)
	}
}
