package cli

import (
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// F39: requireCallerAdmin is gated unavailable for M1, so the
// KEYLATCH_MEMBER_ID environment value is never consulted against the team
// roster — a removed admin's ID cannot pass the admin check. Active
// authenticated subject plus session/rotation revocation remains expansion
// work for when team mutation re-enters scope.
func TestSecurityRegression_F39_RemovedAdmin(t *testing.T) {
	t.Setenv("KEYLATCH_MEMBER_ID", "removed-admin")
	tm := &team.Team{Members: []team.Member{{ID: "removed-admin", Role: team.RoleAdmin, Status: team.MemberRemoved}}}
	if requireCallerAdmin(tm) == nil {
		t.Fatal("removed admin authorized solely by environment-selected member ID")
	}
}
