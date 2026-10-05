//go:build securitysuite

package runner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
)

type auditGateway struct{}

func (auditGateway) Addr() string  { return "127.0.0.1:7878" }
func (auditGateway) Running() bool { return true }

// KNOWN-FAILING: gatewayTypedChildEnv only strips KEYLATCH_* vars via
// internal/runtime.FilterChildEnv instead of building from an allowlist, so
// BW_SESSION and OP_SERVICE_ACCOUNT_TOKEN survive into child environments.
func TestSecurityRegression_GatewayMustStripManagerAuthentication(t *testing.T) {
	t.Setenv("BW_SESSION", "synthetic-manager-session")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-service-account")
	env := gatewayTypedChildEnv(registry.ConnectionTemplate{}, "http://127.0.0.1:7878", "synthetic-scoped-token", false, nil)
	for _, v := range env {
		if strings.HasPrefix(v, "BW_SESSION=") || strings.HasPrefix(v, "OP_SERVICE_ACCOUNT_TOKEN=") {
			t.Errorf("manager authentication inherited: %s", strings.SplitN(v, "=", 2)[0])
		}
	}
}

// KNOWN-FAILING: gatewayTypedDriver.Run hardcodes
// token.TokenSpec.LLMSession = false and never sets MaxUses or revokes on
// child exit, so gateway tokens misclassify agent runs as human runs with
// unbounded, unrevoked leases.
func TestSecurityRegression_GatewayTokenMustPreserveLLMClassification(t *testing.T) {
	t.Setenv("CREDENTIALS_LLM_SESSION", "audit")
	path := filepath.Join(t.TempDir(), "tokens.json")
	d := NewGatewayTypedDriver(auditGateway{}, make([]byte, 32), path)
	_, err := d.Run(context.Background(), ExecRequest{Command: []string{"/bin/true"}}, registry.ConnectionTemplate{Provider: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	records, err := token.List(token.ListOpts{}, path)
	if err != nil || len(records) != 1 {
		t.Fatalf("token list: %v, count %d", err, len(records))
	}
	if !records[0].LLMSession {
		t.Error("LLM child received token marked non-LLM")
	}
	if records[0].MaxUses == 0 {
		t.Error("token has unlimited uses")
	}
	if !records[0].Revoked {
		t.Error("token remains active after child exits")
	}
}
