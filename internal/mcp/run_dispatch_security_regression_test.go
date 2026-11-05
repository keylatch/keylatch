package mcp

import (
	"strings"
	"testing"
)

// keylatch_run executes an allowed command through the runtime dispatcher, not
// by calling the command runner directly, so the child's environment is the
// one the runtime layer scopes and no password-manager session reaches the
// tool output.
func TestSecurityRegression_MCPMustExecuteAllowedCommandViaRuntime(t *testing.T) {
	provider, sh := shellProvider(t, "audit-f05-shell", "sh ")

	t.Setenv("BW_SESSION", "audit-synthetic-session-9284")
	body, isErr := callRunHandler(t, newMockStore(), realDispatcher(t, &recordingEmitter{}), map[string]any{
		"provider": provider,
		"command":  []any{sh, "-c", "echo \"$BW_SESSION\""},
	})
	if isErr {
		t.Fatalf("unexpected handler failure: %s", body)
	}
	if strings.Contains(body, "audit-synthetic-session-9284") {
		t.Error("synthetic password-manager session returned in MCP tool output")
	}
}
