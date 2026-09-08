//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package cli

import (
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// KNOWN-FAILING (F39): requireCallerAdmin authorizes solely from the
// KEYLATCH_MEMBER_ID environment value against the team roster, so a
// removed admin's ID still passes the admin check.
func TestSecurityRegression_F39_RemovedAdmin(t *testing.T) {
	t.Setenv("KEYLATCH_MEMBER_ID", "removed-admin")
	tm := &team.Team{Members: []team.Member{{ID: "removed-admin", Role: team.RoleAdmin, Status: team.MemberRemoved}}}
	if requireCallerAdmin(tm) == nil {
		t.Fatal("removed admin authorized solely by environment-selected member ID")
	}
}
