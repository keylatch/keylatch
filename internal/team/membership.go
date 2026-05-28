package team

import (
	"context"
	"fmt"
)

// OnRotateSharedSecrets is a callback invoked when a member is removed.
// It is called with the team and removed member ID so that shared-secret
// rotation (FIND3-006) can be triggered by the sharedsecret package.
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

// RemoveMember sets a member's status to removed and triggers shared-secret rotation (FIND3-006).
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
	// FIND3-006: trigger shared-secret rotation.
	if OnRotateSharedSecrets != nil {
		if err := OnRotateSharedSecrets(ctx, t, memberID); err != nil {
			return fmt.Errorf("team: rotation callback failed: %w", err)
		}
	}
	return nil
}

// Transfer changes the team owner to newOwnerID.
// The previous owner is downgraded to admin.
func Transfer(_ context.Context, t *Team, newOwnerID string) error {
	found := false
	for i := range t.Members {
		if t.Members[i].ID == newOwnerID {
			if t.Members[i].Status != MemberActive {
				return fmt.Errorf("team: cannot transfer ownership to non-active member %q", newOwnerID)
			}
			found = true
		}
	}
	if !found {
		return ErrMemberNotFound
	}

	// Demote current owners, promote new owner.
	for i := range t.Members {
		if t.Members[i].Role == RoleOwner {
			t.Members[i].Role = RoleAdmin
		}
		if t.Members[i].ID == newOwnerID {
			t.Members[i].Role = RoleOwner
		}
	}
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

// FindMember returns the member with the given ID, or ErrMemberNotFound.
// M-7: used by CLI commands to look up caller identity before privilege checks.
func FindMember(t *Team, memberID string) (Member, error) {
	for _, m := range t.Members {
		if m.ID == memberID {
			return m, nil
		}
	}
	return Member{}, ErrMemberNotFound
}
