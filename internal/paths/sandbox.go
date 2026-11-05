package paths

import (
	"path/filepath"
	"slices"
)

// SandboxReadDenies hides Keylatch state, OS keyrings and the session bus from agent shells.
func SandboxReadDenies(lookup Lookup) []string {
	out := []string{
		"~/.keylatch", "~/.config/keylatch", "~/.local/share/keyrings", "~/Library/Keychains",
		ConfigDir(lookup), Config(lookup), Vault(lookup), KeyringDir(lookup), KeyringPath(lookup), KeyringIdentityPath(lookup),
		GatewayDir(lookup), GatewaySigningKey(lookup), AuditKeyWrapped(lookup), GrantAccessorKey(lookup),
	}
	if runtimeDir := lookup("XDG_RUNTIME_DIR"); runtimeDir != "" {
		out = append(out, filepath.Join(runtimeDir, "bus"))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
