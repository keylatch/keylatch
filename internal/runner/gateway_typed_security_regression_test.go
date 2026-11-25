package runner

import (
	"strings"
	"testing"

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
