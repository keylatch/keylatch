package team

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

// RequireRole returns ErrRoleInsufficient if the caller's role is below minRole.
// Enforcement happens here, not at CLI layer.
func RequireRole(member Member, minRole Role) error {
	if RoleLevel(member.Role) < RoleLevel(minRole) {
		return ErrRoleInsufficient
	}
	return nil
}
