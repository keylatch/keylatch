package team

import "errors"

// Authorization errors for membership changes.
var (
	ErrInvalidRole        = errors.New("unknown role")
	ErrOwnerViaTransfer   = errors.New("the owner role is assigned only by an ownership transfer from the current owner")
	ErrOwnerOnly          = errors.New("only the current team owner can transfer ownership")
	ErrOwnerProtected     = errors.New("the team owner's role and membership change only through an ownership transfer")
	ErrActorInactive      = errors.New("acting member is not active")
	ErrRoleAboveActor     = errors.New("cannot assign a role at or above your own")
	ErrTargetAtOrAboveYou = errors.New("cannot change a member whose role is at or above your own")
)

// RoleLevel maps roles to integers for comparison.
// Higher integer = higher privilege.
func RoleLevel(r Role) int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleDeveloper:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// ValidRole reports whether r is one of the defined roles.
func ValidRole(r Role) bool {
	return RoleLevel(r) > 0
}

// RequireRole returns ErrRoleInsufficient if the caller's role is below minRole.
// Enforcement happens here, not at CLI layer.
func RequireRole(member Member, minRole Role) error {
	if RoleLevel(member.Role) < RoleLevel(minRole) {
		return ErrRoleInsufficient
	}
	return nil
}

// requireActiveAdmin checks that actor is active and holds at least admin.
func requireActiveAdmin(actor Member) error {
	if actor.Status != MemberActive {
		return ErrActorInactive
	}
	return RequireRole(actor, RoleAdmin)
}

// AuthorizeRoleChange checks whether actor may set target's role to newRole.
// Ownership never moves through a role change, the owner's role is fixed
// until a transfer, and an actor can neither grant a role at or above its
// own nor change a member at or above its own role.
func AuthorizeRoleChange(actor, target Member, newRole Role) error {
	if !ValidRole(newRole) {
		return ErrInvalidRole
	}
	if newRole == RoleOwner {
		return ErrOwnerViaTransfer
	}
	if err := requireActiveAdmin(actor); err != nil {
		return err
	}
	if target.Role == RoleOwner {
		return ErrOwnerProtected
	}
	if RoleLevel(newRole) >= RoleLevel(actor.Role) {
		return ErrRoleAboveActor
	}
	if RoleLevel(target.Role) >= RoleLevel(actor.Role) {
		return ErrTargetAtOrAboveYou
	}
	return nil
}

// AuthorizeRemoval checks whether actor may remove target from the team.
func AuthorizeRemoval(actor, target Member) error {
	if err := requireActiveAdmin(actor); err != nil {
		return err
	}
	if target.Role == RoleOwner {
		return ErrOwnerProtected
	}
	if RoleLevel(target.Role) >= RoleLevel(actor.Role) {
		return ErrTargetAtOrAboveYou
	}
	return nil
}

// AuthorizeInvite checks whether actor may invite a member with role.
func AuthorizeInvite(actor Member, role Role) error {
	if !ValidRole(role) {
		return ErrInvalidRole
	}
	if role == RoleOwner {
		return ErrOwnerViaTransfer
	}
	if err := requireActiveAdmin(actor); err != nil {
		return err
	}
	if RoleLevel(role) >= RoleLevel(actor.Role) {
		return ErrRoleAboveActor
	}
	return nil
}

// AuthorizeTransfer checks whether actor may hand ownership to newOwner.
func AuthorizeTransfer(actor, newOwner Member) error {
	if actor.Status != MemberActive {
		return ErrActorInactive
	}
	if actor.Role != RoleOwner {
		return ErrOwnerOnly
	}
	if newOwner.ID == actor.ID {
		return errors.New("you already own the team")
	}
	if newOwner.Status != MemberActive {
		return errors.New("ownership can only go to an active member")
	}
	return nil
}
