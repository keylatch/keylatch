package runner

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
)

// The gateway child environment carries no manager authentication.
func TestSecurityRegression_GatewayMustStripManagerAuthentication(t *testing.T) {
	t.Setenv("BW_SESSION", "synthetic-manager-session")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-service-account")
	t.Setenv("OP_SESSION_synthetic", "synthetic-cli-session")
	preserve := []string{"BW_SESSION", "OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_synthetic"}
	envs := map[string][]string{
		"default": gatewayTypedChildEnv(registry.ConnectionTemplate{}, "http://127.0.0.1:7878", "synthetic-scoped-token", false, nil),
		"clean":   gatewayTypedChildEnv(registry.ConnectionTemplate{}, "http://127.0.0.1:7878", "synthetic-scoped-token", true, preserve),
	}
	for mode, env := range envs {
		for _, v := range env {
			name := strings.SplitN(v, "=", 2)[0]
			if name == "BW_SESSION" || name == "OP_SERVICE_ACCOUNT_TOKEN" || name == "OP_SESSION_synthetic" {
				t.Errorf("%s env: manager authentication inherited: %s", mode, name)
			}
		}
	}
}

func TestSecurityRegression_GatewayTokenMustPreserveLLMClassification(t *testing.T) {
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true on PATH")
	}
	t.Setenv("CREDENTIALS_LLM_SESSION", "1")
	path := filepath.Join(t.TempDir(), "tokens.json")
	d := NewGatewayTypedDriver(auditGateway{}, make([]byte, 32), path)
	_, err = d.Run(context.Background(), ExecRequest{Command: []string{trueBin}}, registry.ConnectionTemplate{Provider: "child-token"})
	if err != nil {
		t.Fatal(err)
	}
	records, err := token.List(token.ListOpts{IncludeRevoked: true}, path)
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
