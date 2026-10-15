//go:build securitysuite

package runner

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

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
