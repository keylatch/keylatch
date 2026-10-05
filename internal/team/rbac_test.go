package team_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

func member(id string, role team.Role) team.Member {
	return team.Member{ID: id, Role: role, Status: team.MemberActive}
}

func TestAuthorizeRoleChange(t *testing.T) {
	owner := member("owner", team.RoleOwner)
	admin := member("admin", team.RoleAdmin)
	admin2 := member("admin2", team.RoleAdmin)
	dev := member("dev", team.RoleDeveloper)
	viewer := member("viewer", team.RoleViewer)
	removedAdmin := team.Member{ID: "gone", Role: team.RoleAdmin, Status: team.MemberRemoved}

	cases := []struct {
		name    string
		actor   team.Member
		target  team.Member
		role    team.Role
		wantErr error
	}{
		{"admin cannot make itself owner", admin, admin, team.RoleOwner, team.ErrOwnerViaTransfer},
		{"owner cannot assign owner by role change", owner, admin, team.RoleOwner, team.ErrOwnerViaTransfer},
		{"admin cannot promote a developer to owner", admin, dev, team.RoleOwner, team.ErrOwnerViaTransfer},
		{"admin cannot promote a developer to admin", admin, dev, team.RoleAdmin, team.ErrRoleAboveActor},
		{"admin cannot demote the owner", admin, owner, team.RoleViewer, team.ErrOwnerProtected},
		{"owner cannot change its own role", owner, owner, team.RoleAdmin, team.ErrOwnerProtected},
		{"admin cannot demote another admin", admin, admin2, team.RoleViewer, team.ErrTargetAtOrAboveYou},
		{"developer cannot change roles", dev, viewer, team.RoleViewer, team.ErrRoleInsufficient},
		{"removed admin cannot change roles", removedAdmin, dev, team.RoleViewer, team.ErrActorInactive},
		{"unknown role rejected", owner, dev, team.Role("superuser"), team.ErrInvalidRole},
		{"empty role rejected", owner, dev, team.Role(""), team.ErrInvalidRole},
		{"case-changed owner rejected", admin, dev, team.Role("Owner"), team.ErrInvalidRole},
		{"admin demotes a developer", admin, dev, team.RoleViewer, nil},
		{"admin promotes a viewer to developer", admin, viewer, team.RoleDeveloper, nil},
		{"owner promotes a developer to admin", owner, dev, team.RoleAdmin, nil},
		{"owner demotes an admin", owner, admin, team.RoleDeveloper, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := team.AuthorizeRoleChange(tc.actor, tc.target, tc.role)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthorizeRemovalProtectsOwnerAndPeers(t *testing.T) {
	owner := member("owner", team.RoleOwner)
	admin := member("admin", team.RoleAdmin)
	if err := team.AuthorizeRemoval(admin, owner); !errors.Is(err, team.ErrOwnerProtected) {
		t.Fatalf("admin removing owner: err = %v", err)
	}
	if err := team.AuthorizeRemoval(admin, member("admin2", team.RoleAdmin)); !errors.Is(err, team.ErrTargetAtOrAboveYou) {
		t.Fatalf("admin removing admin: err = %v", err)
	}
	if err := team.AuthorizeRemoval(admin, member("dev", team.RoleDeveloper)); err != nil {
		t.Fatalf("admin removing developer: %v", err)
	}
	if err := team.AuthorizeRemoval(owner, admin); err != nil {
		t.Fatalf("owner removing admin: %v", err)
	}
}

func TestAuthorizeInviteNeverGrantsOwner(t *testing.T) {
	owner := member("owner", team.RoleOwner)
	admin := member("admin", team.RoleAdmin)
	if err := team.AuthorizeInvite(owner, team.RoleOwner); !errors.Is(err, team.ErrOwnerViaTransfer) {
		t.Fatalf("invite as owner: err = %v", err)
	}
	if err := team.AuthorizeInvite(admin, team.RoleAdmin); !errors.Is(err, team.ErrRoleAboveActor) {
		t.Fatalf("admin inviting admin: err = %v", err)
	}
	if err := team.AuthorizeInvite(owner, team.RoleAdmin); err != nil {
		t.Fatalf("owner inviting admin: %v", err)
	}
}

func transferFixture(t *testing.T) *team.Team {
	t.Helper()
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	tm := &team.Team{ID: "team", Members: []team.Member{
		member("owner", team.RoleOwner),
		member("admin", team.RoleAdmin),
		member("dev", team.RoleDeveloper),
		{ID: "suspended", Role: team.RoleDeveloper, Status: team.MemberSuspended},
	}}
	if err := team.Save(context.Background(), tm); err != nil {
		t.Fatal(err)
	}
	return tm
}

func roleOf(t *testing.T, id string) team.Role {
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

func TestTransferOnlyByOwner(t *testing.T) {
	ctx := context.Background()
	tm := transferFixture(t)

	if err := team.Transfer(ctx, tm, "admin", "admin"); !errors.Is(err, team.ErrOwnerOnly) {
		t.Fatalf("admin self-transfer: err = %v", err)
	}
	if err := team.Transfer(ctx, tm, "dev", "dev"); !errors.Is(err, team.ErrOwnerOnly) {
		t.Fatalf("developer self-transfer: err = %v", err)
	}
	if err := team.Transfer(ctx, tm, "nobody", "admin"); !errors.Is(err, team.ErrMemberNotFound) {
		t.Fatalf("unknown actor: err = %v", err)
	}
	if err := team.Transfer(ctx, tm, "owner", "suspended"); err == nil {
		t.Fatal("transfer to a suspended member succeeded")
	}
	if got := roleOf(t, "admin"); got != team.RoleAdmin {
		t.Fatalf("admin role changed to %q by refused transfers", got)
	}

	if err := team.Transfer(ctx, tm, "owner", "admin"); err != nil {
		t.Fatalf("owner transfer: %v", err)
	}
	if got := roleOf(t, "admin"); got != team.RoleOwner {
		t.Fatalf("new owner role = %q", got)
	}
	if got := roleOf(t, "owner"); got != team.RoleAdmin {
		t.Fatalf("previous owner role = %q, want admin", got)
	}
}

func TestChangeRolePersistsOnlyAuthorizedChanges(t *testing.T) {
	ctx := context.Background()
	tm := transferFixture(t)

	if err := team.ChangeRole(ctx, tm, "admin", "admin", team.RoleOwner); !errors.Is(err, team.ErrOwnerViaTransfer) {
		t.Fatalf("admin self-promotion: err = %v", err)
	}
	if err := team.ChangeRole(ctx, tm, "admin", "owner", team.RoleViewer); !errors.Is(err, team.ErrOwnerProtected) {
		t.Fatalf("admin demoting owner: err = %v", err)
	}
	if got := roleOf(t, "owner"); got != team.RoleOwner {
		t.Fatalf("owner role = %q after refused changes", got)
	}
	if err := team.ChangeRole(ctx, tm, "admin", "dev", team.RoleViewer); err != nil {
		t.Fatalf("admin demoting developer: %v", err)
	}
	if got := roleOf(t, "dev"); got != team.RoleViewer {
		t.Fatalf("dev role = %q, want viewer", got)
	}
}
