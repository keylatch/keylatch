package team_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

// A roster where one ID is both a developer and the owner: an admin is
// authorized against the developer entry, so the change must never reach
// the owner entry.
func duplicateRoster() *team.Team {
	return &team.Team{ID: "team", Members: []team.Member{
		member("owner", team.RoleOwner),
		member("admin", team.RoleAdmin),
		member("shared", team.RoleDeveloper),
		member("shared", team.RoleOwner),
	}}
}

func TestLoadRejectsDuplicateMemberIDs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	data, err := json.Marshal(duplicateRoster())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "team.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := team.Load(context.Background()); !errors.Is(err, team.ErrDuplicateMember) {
		t.Fatalf("Load = %v, want ErrDuplicateMember", err)
	}
}

func TestMembershipChangesRefuseDuplicateMemberIDs(t *testing.T) {
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	ctx := context.Background()

	tm := duplicateRoster()
	if err := team.ChangeRole(ctx, tm, "admin", "shared", team.RoleViewer); !errors.Is(err, team.ErrDuplicateMember) {
		t.Fatalf("ChangeRole = %v, want ErrDuplicateMember", err)
	}
	if tm.Members[3].Role != team.RoleOwner {
		t.Fatalf("owner entry changed to %q", tm.Members[3].Role)
	}
	if err := team.Transfer(ctx, tm, "owner", "admin"); !errors.Is(err, team.ErrDuplicateMember) {
		t.Fatalf("Transfer = %v, want ErrDuplicateMember", err)
	}
	if err := team.Save(ctx, tm); !errors.Is(err, team.ErrDuplicateMember) {
		t.Fatalf("Save = %v, want ErrDuplicateMember", err)
	}
}

func TestTransferChangesOnlyTheTwoMembers(t *testing.T) {
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	tm := &team.Team{ID: "team", Members: []team.Member{
		member("owner", team.RoleOwner),
		member("admin", team.RoleAdmin),
		member("dev", team.RoleDeveloper),
	}}
	if err := team.Transfer(context.Background(), tm, "owner", "dev"); err != nil {
		t.Fatal(err)
	}
	want := []team.Role{team.RoleAdmin, team.RoleAdmin, team.RoleOwner}
	for i, m := range tm.Members {
		if m.Role != want[i] {
			t.Fatalf("member %s role = %q, want %q", m.ID, m.Role, want[i])
		}
	}
}

func TestJoinKeepsExistingTeamFile(t *testing.T) {
	b, key := issueInvite(t)
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	if _, err := team.Join(ctx, encodeInvite(t, b), key); err != nil {
		t.Fatalf("first Join: %v", err)
	}
	joined, err := team.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	joined.Members = append(joined.Members, member("owner", team.RoleOwner))
	if err := team.Save(ctx, joined); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "team.json"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := team.Join(ctx, encodeInvite(t, b), key); !errors.Is(err, team.ErrAlreadyJoined) {
		t.Fatalf("second Join = %v, want ErrAlreadyJoined", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "team.json"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("team file replaced by a second Join: %v", err)
	}
}
