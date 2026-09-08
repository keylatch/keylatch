package cli

import (
	"testing"

	"github.com/keylatch/keylatch/internal/runtime"
)

// KNOWN-FAILING (F04): RequireVerifiedSession accepts any nonempty
// KEYLATCH_LLM_TICKET, and GuardRuntime allows all currently listed modes;
// neither verifies signature, issuer, expiry, or process binding.
func TestSecurityRegression_F04_UnverifiedTicketMustNotAuthorizeDirectRuntime(t *testing.T) {
	env := func(k string) string {
		if k == "KEYLATCH_LLM_TICKET" {
			return "not-a-signed-ticket"
		}
		return ""
	}
	err := RequireVerifiedSession(env, true, false)
	blocked, _ := GuardRuntime(runtime.RuntimeDirectBrokered, "", env, nil)
	if err == nil && !blocked {
		t.Error("arbitrary ticket text passes both raw-exposure gates")
	}
}
