package mcp

import (
	"os/exec"
	"strings"
	"testing"

	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/registry"
)

// KNOWN-FAILING (F05): makeRunHandler bypasses runtime dispatch and calls
// internal/exec.CommandRunner.Run directly, inheriting the full process
// environment instead of an env scoped by the runtime layer.
func TestSecurityRegression_F05_MCPMustExecuteAllowedCommandViaRuntime(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	// commandMatchesAllowlist does a literal string-prefix match on the
	// joined command line, and makeRunHandler passes command[0] straight to
	// runner.Run without resolving it — so the allowed prefix and the exec
	// name must be the same absolute path for a real DefaultRunner call to
	// reach the leak surface at all.
	provider := "audit-f05-shell"
	_ = registry.Register(registry.ConnectionTemplate{
		Provider:               provider,
		DisplayName:            "Audit F05 Shell",
		Category:               "test",
		AuthFlow:               "api_key",
		StoragePathTpl:         "default/test/" + provider + "/default",
		TrustLevel:             registry.TrustLocalOnly,
		SecretFields:           []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		AllowedCommandPrefixes: []string{sh + " "},
		TestStrategy:           registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
	})

	t.Setenv("BW_SESSION", "audit-synthetic-session-9284")
	body, isErr := callRunHandler(t, newMockStore(), internalexec.DefaultRunner, map[string]any{
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
