package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/testutil"
)

func writeRosterFixture(t *testing.T) string {
	t.Helper()
	dir := setupTeamDir(t)
	tm := &team.Team{ID: "team", Members: []team.Member{
		{ID: "owner", Role: team.RoleOwner, Status: team.MemberActive},
		{ID: "admin", Role: team.RoleAdmin, Status: team.MemberActive},
		{ID: "dev", Role: team.RoleDeveloper, Status: team.MemberActive},
	}}
	if err := team.Save(context.Background(), tm); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "team.json")
}

func actAs(t *testing.T, id string) {
	t.Helper()
	prev := teamActor
	teamActor = func(tm *team.Team) (team.Member, error) { return team.FindMember(tm, id) }
	t.Cleanup(func() { teamActor = prev })
}

func runTeam(t *testing.T, args ...string) error {
	t.Helper()
	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"team"}, args...))
	return root.Execute()
}

func rosterRole(t *testing.T, id string) team.Role {
	t.Helper()
	tm, err := team.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, err := team.FindMember(tm, id)
	if err != nil {
		t.Fatal(err)
	}
	return m.Role
}

// A member ID supplied through the environment must never act as the caller's
// identity: every membership change fails closed and the roster is untouched.
func TestTeamChangesIgnoreEnvironmentIdentity(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	path := writeRosterFixture(t)
	t.Setenv("KEYLATCH_MEMBER_ID", "owner")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"role", "--id", "admin", "--role", "owner"},
		{"transfer", "--to", "admin"},
		{"remove", "--id", "owner"},
		{"invite", "--email-hmac", "abc", "--role", "owner"},
	} {
		if err := runTeam(t, args...); err == nil {
			t.Errorf("team %v succeeded without an authenticated identity", args)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("team roster changed")
	}
}

func TestTeamRoleCannotCreateOwner(t *testing.T) {
	writeRosterFixture(t)
	actAs(t, "admin")

	err := runTeam(t, "role", "--id", "admin", "--role", "owner")
	if !errors.Is(err, team.ErrOwnerViaTransfer) {
		t.Fatalf("admin self-promotion: err = %v", err)
	}
	if err := runTeam(t, "role", "--id", "dev", "--role", "admin"); !errors.Is(err, team.ErrRoleAboveActor) {
		t.Fatalf("admin promoting to admin: err = %v", err)
	}
	if err := runTeam(t, "role", "--id", "owner", "--role", "viewer"); !errors.Is(err, team.ErrOwnerProtected) {
		t.Fatalf("admin demoting owner: err = %v", err)
	}
	if rosterRole(t, "admin") != team.RoleAdmin || rosterRole(t, "owner") != team.RoleOwner || rosterRole(t, "dev") != team.RoleDeveloper {
		t.Fatal("refused role changes modified the roster")
	}
	if err := runTeam(t, "role", "--id", "dev", "--role", "viewer"); err != nil {
		t.Fatalf("admin demoting developer: %v", err)
	}
	if got := rosterRole(t, "dev"); got != team.RoleViewer {
		t.Fatalf("dev role = %q, want viewer", got)
	}
}

func TestTeamRemoveCannotRemoveOwner(t *testing.T) {
	writeRosterFixture(t)
	actAs(t, "admin")
	if err := runTeam(t, "remove", "--id", "owner"); !errors.Is(err, team.ErrOwnerProtected) {
		t.Fatalf("admin removing owner: err = %v", err)
	}
}

func TestTeamInviteCannotGrantOwner(t *testing.T) {
	writeRosterFixture(t)
	actAs(t, "owner")
	if err := runTeam(t, "invite", "--email-hmac", "abc", "--role", "owner"); !errors.Is(err, team.ErrOwnerViaTransfer) {
		t.Fatalf("owner invite: err = %v", err)
	}
}

func TestTeamTransferOwnerOnly(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	writeRosterFixture(t)

	actAs(t, "admin")
	if err := runTeam(t, "transfer", "--to", "admin"); !errors.Is(err, team.ErrOwnerOnly) {
		t.Fatalf("admin transfer to self: err = %v", err)
	}
	if rosterRole(t, "admin") != team.RoleAdmin {
		t.Fatal("refused transfer changed the roster")
	}

	actAs(t, "owner")
	if err := runTeam(t, "transfer", "--to", "admin"); err != nil {
		t.Fatalf("owner transfer: %v", err)
	}
	if rosterRole(t, "admin") != team.RoleOwner || rosterRole(t, "owner") != team.RoleAdmin {
		t.Fatal("transfer did not move ownership")
	}
}

func TestTeamTransferNeedsHumanTerminal(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeRosterFixture(t)
	actAs(t, "owner")

	withInteractiveStdin(t, false)
	assertSecurityBlock(t, runTeam(t, "transfer", "--to", "admin"))

	withInteractiveStdin(t, true)
	t.Setenv("CLAUDECODE", "1")
	assertSecurityBlock(t, runTeam(t, "transfer", "--to", "admin"))

	if rosterRole(t, "owner") != team.RoleOwner {
		t.Fatal("blocked transfer changed the roster")
	}
}
