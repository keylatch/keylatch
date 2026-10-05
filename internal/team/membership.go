package team

import (
	"context"
	"fmt"
)

// OnRotateSharedSecrets is a callback invoked when a member is removed.
// It is called with the team and removed member ID so that shared-secret
// rotation can be triggered by the sharedsecret package.
// Default: no-op.
var OnRotateSharedSecrets func(ctx context.Context, t *Team, memberID string) error

// AddMember adds a new member to the team and persists the change.
func AddMember(_ context.Context, t *Team, m Member) error {
	// Check for duplicate.
	for _, existing := range t.Members {
		if existing.ID == m.ID {
			return fmt.Errorf("team: member %q already exists", m.ID)
		}
	}
	t.Members = append(t.Members, m)
	return writeTeam(t)
}

// RemoveMember sets a member's status to removed and triggers shared-secret rotation.
func RemoveMember(ctx context.Context, t *Team, memberID string) error {
	found := false
	for i := range t.Members {
		if t.Members[i].ID == memberID {
			t.Members[i].Status = MemberRemoved
			found = true
			break
		}
	}
	if !found {
		return ErrMemberNotFound
	}
	if err := writeTeam(t); err != nil {
		return err
	}
	// trigger shared-secret rotation.
	if OnRotateSharedSecrets != nil {
		if err := OnRotateSharedSecrets(ctx, t, memberID); err != nil {
			return fmt.Errorf("team: rotation callback failed: %w", err)
		}
	}
	return nil
}

// Transfer hands ownership from actorID, who must be the active owner, to
// newOwnerID. The previous owner becomes admin.
func Transfer(_ context.Context, t *Team, actorID, newOwnerID string) error {
	if err := checkUniqueMembers(t); err != nil {
		return err
	}
	actor, err := FindMember(t, actorID)
	if err != nil {
		return err
	}
	newOwner, err := FindMember(t, newOwnerID)
	if err != nil {
		return err
	}
	if err := AuthorizeTransfer(actor, newOwner); err != nil {
		return err
	}
	ai, ni := memberIndex(t, actorID), memberIndex(t, newOwnerID)
	t.Members[ai].Role = RoleAdmin
	t.Members[ni].Role = RoleOwner
	return writeTeam(t)
}

// ChangeRole sets targetID's role on behalf of actorID after
// AuthorizeRoleChange allows it, and persists the team.
func ChangeRole(_ context.Context, t *Team, actorID, targetID string, newRole Role) error {
	if err := checkUniqueMembers(t); err != nil {
		return err
	}
	actor, err := FindMember(t, actorID)
	if err != nil {
		return err
	}
	target, err := FindMember(t, targetID)
	if err != nil {
		return err
	}
	if err := AuthorizeRoleChange(actor, target, newRole); err != nil {
		return err
	}
	t.Members[memberIndex(t, targetID)].Role = newRole
	return writeTeam(t)
}

// ActiveMembers returns all members with status=active.
func ActiveMembers(t *Team) []Member {
	var out []Member
	for _, m := range t.Members {
		if m.Status == MemberActive {
			out = append(out, m)
		}
	}
	return out
}

// memberIndex returns the index of the entry FindMember returns for id. The
// caller must have found the member already.
func memberIndex(t *Team, id string) int {
	for i := range t.Members {
		if t.Members[i].ID == id {
			return i
		}
	}
	return -1
}

// FindMember returns the member with the given ID, or ErrMemberNotFound.
// Used by CLI commands to look up caller identity before privilege checks.
func FindMember(t *Team, memberID string) (Member, error) {
	for _, m := range t.Members {
		if m.ID == memberID {
			return m, nil
		}
	}
	return Member{}, ErrMemberNotFound
}
