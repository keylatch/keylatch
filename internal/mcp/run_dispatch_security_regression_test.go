//go:build securitysuite

package mcp

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

type fakeGateway struct{}

func (fakeGateway) Addr() string  { return "127.0.0.1:1" }
func (fakeGateway) Running() bool { return true }

func TestSecurityRegression_MCPMustExecuteAllowedCommandViaRuntime(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not available: %v", err)
	}
	// The allowlist pre-flight matches the joined command line by string prefix
	// and the dispatcher matches command[0], so both use the same absolute path.
	provider := "mcp-dispatch-shell"
	_ = registry.Register(registry.ConnectionTemplate{
		Provider:               provider,
		DisplayName:            "MCP Dispatch Shell",
		Category:               "test",
		AuthFlow:               "api_key",
		StoragePathTpl:         "default/test/" + provider + "/default",
		TrustLevel:             registry.TrustLocalOnly,
		SecretFields:           []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		AllowedCommandPrefixes: []string{sh + " "},
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		TestStrategy: registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
	})

	dispatcher := runner.DispatchRunner{Drivers: map[string]runner.Driver{
		"gateway_typed": runner.NewGatewayTypedDriver(fakeGateway{}, make([]byte, 32), filepath.Join(t.TempDir(), "tokens.json")),
	}}

	t.Setenv("BW_SESSION", "audit-synthetic-session-9284")
	body, isErr := callRunHandler(t, newMockStore(), dispatcher, map[string]any{
		"provider": provider,
		"command":  []any{sh, "-c", "echo \"$BW_SESSION:$KEYLATCH_RUNTIME\""},
	})
	if isErr {
		t.Fatalf("unexpected handler failure: %s", body)
	}
	if strings.Contains(body, "audit-synthetic-session-9284") {
		t.Error("synthetic password-manager session returned in MCP tool output")
	}
	if !strings.Contains(body, "gateway_typed") {
		t.Errorf("command did not run through runtime dispatch: %s", body)
	}
}
