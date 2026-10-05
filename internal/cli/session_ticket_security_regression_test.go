package cli

import (
	"testing"

	"github.com/keylatch/keylatch/internal/runtime"
)

// TestSecurityRegression_UnverifiedTicketMustNotAuthorizeDirectRuntime checks
// that arbitrary ticket text in the environment cannot open a raw-credential
// path.
func TestSecurityRegression_UnverifiedTicketMustNotAuthorizeDirectRuntime(t *testing.T) {
	env := func(k string) string {
		if k == "KEYLATCH_SESSION_TICKET" {
			return "not-a-signed-ticket"
		}
		return ""
	}
	err := RequireRawCredentialOptIn(true, false)
	blocked, _ := GuardRuntime(runtime.RuntimeDirectBrokered, "", env, nil)
	if err == nil && !blocked {
		t.Error("arbitrary ticket text passes both raw-exposure gates")
	}
}
