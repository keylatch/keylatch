// Package paths is the single source of truth for default path resolution and
// environment variable overrides in keylatch. All other packages must call
// these functions rather than reading KEYLATCH_* env vars directly.
//
// Security invariant: no hardcoded /Users/<name>/, /home/<name>/, or
// repo-relative paths may appear here.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Lookup is an alias for llmcontext.Lookup so callers only import this package.
type Lookup = llmcontext.Lookup

// Forward-compat env var constants. Declared here so the entire
// path-discovery surface is documented in one place. No exported
// functions yet — this functionality ships later.
const (
	// EnvTrustAllowlistPath is the env var for the PKCS #11 module allowlist.
	// Default: ~/.keylatch/trust-allowlist.json
	EnvTrustAllowlistPath = "KEYLATCH_TRUST_ALLOWLIST_PATH"

	// EnvTeamDir is the env var for the team state directory.
	// Default: ~/.keylatch/team/
	EnvTeamDir = "KEYLATCH_TEAM_DIR"

	// EnvOrgPolicyDir is the env var for installed org policy bundles.
	// Default: ~/.keylatch/team/org-policy/
	EnvOrgPolicyDir = "KEYLATCH_ORG_POLICY_DIR"
)

// configDirName is the base directory name under the home directory.
const configDirName = ".keylatch"

// ConfigDir returns the keylatch configuration directory.
//
// Resolution order:
//   - KEYLATCH_CONFIG_DIR (all platforms)
//   - Linux: $XDG_CONFIG_HOME/keylatch → ~/.config/keylatch → ~/.keylatch
//   - macOS/Windows: ~/.keylatch
func ConfigDir(env Lookup) string {
	if v := env("KEYLATCH_CONFIG_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "linux" {
		if xdg := env("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "keylatch")
		}
		// Fall back to ~/.config/keylatch, then ~/.keylatch
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, ".config", "keylatch")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Last resort: relative path (should never happen in practice).
		return configDirName
	}
	return filepath.Join(home, configDirName)
}

// Config returns the path to the main configuration file.
// Override: KEYLATCH_CONFIG
func Config(env Lookup) string {
	if v := env("KEYLATCH_CONFIG"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "config.json")
}

// Vault returns the path to the envelope vault directory.
// Override: KEYLATCH_VAULT_PATH
func Vault(env Lookup) string {
	if v := env("KEYLATCH_VAULT_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "vault")
}

// Audit returns the path to the audit log file.
// Override: KEYLATCH_AUDIT_PATH
func Audit(env Lookup) string {
	if v := env("KEYLATCH_AUDIT_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "audit.log")
}

// AuditSalt returns the path to the HMAC salt file.
// Override: KEYLATCH_AUDIT_SALT_PATH
func AuditSalt(env Lookup) string {
	if v := env("KEYLATCH_AUDIT_SALT_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "audit-salt")
}

// Policy returns the path to the policy file.
// Override: KEYLATCH_POLICY_PATH
func Policy(env Lookup) string {
	if v := env("KEYLATCH_POLICY_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "policy.json")
}

// Grants returns the path to the grants JSON file.
// Override: KEYLATCH_GRANTS_PATH
func Grants(env Lookup) string {
	if v := env("KEYLATCH_GRANTS_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "grants.json")
}

// GrantsDir returns the directory that holds per-grant consumption logs.
// Override: KEYLATCH_GRANTS_DIR
func GrantsDir(env Lookup) string {
	if v := env("KEYLATCH_GRANTS_DIR"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "grants")
}

// GrantAccessorKey returns the path to the per-installation HMAC key used to
// compute grant Accessor handles.
// Override: KEYLATCH_GRANT_ACCESSOR_KEY_PATH
func GrantAccessorKey(env Lookup) string {
	if v := env("KEYLATCH_GRANT_ACCESSOR_KEY_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "grant-accessor.key")
}

// Actors returns the path to the actors registry file.
// Override: KEYLATCH_ACTORS_PATH
func Actors(env Lookup) string {
	if v := env("KEYLATCH_ACTORS_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "actors.json")
}

// Projects returns the path to the projects registry file.
// Override: KEYLATCH_PROJECTS_PATH
func Projects(env Lookup) string {
	if v := env("KEYLATCH_PROJECTS_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "projects.json")
}

// KeyringDir returns the directory containing the keyring file.
// Override: KEYLATCH_KEYRING_DIR
func KeyringDir(env Lookup) string {
	if v := env("KEYLATCH_KEYRING_DIR"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "keyring")
}

// KeyringPath returns the path to the keyring.json file.
// Override: KEYLATCH_KEYRING_PATH
func KeyringPath(env Lookup) string {
	if v := env("KEYLATCH_KEYRING_PATH"); v != "" {
		return v
	}
	return filepath.Join(KeyringDir(env), "keyring.json")
}

// KeyringIdentityPath returns the path to the default age-env identity file.
// Bootstrap creates this file when no platform keystore (macOS Keychain, etc.)
// is available. At runtime the factory uses KEYLATCH_AGE_IDENTITY if set;
// otherwise it falls back to this well-known path.
//
// Override: KEYLATCH_KEYRING_IDENTITY_PATH
func KeyringIdentityPath(env Lookup) string {
	if v := env("KEYLATCH_KEYRING_IDENTITY_PATH"); v != "" {
		return v
	}
	return filepath.Join(KeyringDir(env), "identity")
}

// GatewayDir returns the gateway configuration directory.
// Override: KEYLATCH_GATEWAY_DIR
func GatewayDir(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_DIR"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "gateway")
}

// GatewayConfig returns the path to the gateway configuration file.
// Override: KEYLATCH_GATEWAY_CONFIG
func GatewayConfig(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_CONFIG"); v != "" {
		return v
	}
	return filepath.Join(GatewayDir(env), "config.json")
}

// GatewaySigningKey returns the path to the gateway signing key file.
// Override: KEYLATCH_GATEWAY_SIGNING_KEY
func GatewaySigningKey(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_SIGNING_KEY"); v != "" {
		return v
	}
	return filepath.Join(GatewayDir(env), "signing.key")
}

// GatewayPID returns the path to the gateway PID file.
// Override: KEYLATCH_GATEWAY_PID
func GatewayPID(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_PID"); v != "" {
		return v
	}
	return filepath.Join(GatewayDir(env), "gateway.pid")
}

// GatewayLog returns the path to the gateway log file.
// Override: KEYLATCH_GATEWAY_LOG
func GatewayLog(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_LOG"); v != "" {
		return v
	}
	return filepath.Join(GatewayDir(env), "gateway.log")
}

// GatewayTokens returns the path to the gateway tokens JSON file.
// Override: KEYLATCH_GATEWAY_TOKENS
func GatewayTokens(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_TOKENS"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "gateway-tokens.json")
}

// GatewayRules returns the path to the gateway rules JSON file.
// Override: KEYLATCH_GATEWAY_RULES
func GatewayRules(env Lookup) string {
	if v := env("KEYLATCH_GATEWAY_RULES"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "gateway-rules.json")
}

// ApprovalsDir returns the directory that holds approval request files.
// Override: KEYLATCH_APPROVALS_DIR
func ApprovalsDir(env Lookup) string {
	if v := env("KEYLATCH_APPROVALS_DIR"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "approvals")
}

// Sessions returns the path to the sessions file (not yet wired up).
// Override: KEYLATCH_SESSIONS_PATH
func Sessions(env Lookup) string {
	if v := env("KEYLATCH_SESSIONS_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "sessions.json")
}

// Receipts returns the path to the run receipts file.
// Override: KEYLATCH_RECEIPTS_PATH
func Receipts(env Lookup) string {
	if v := env("KEYLATCH_RECEIPTS_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "receipts.json")
}

// DaemonState returns the path to the daemon lifecycle state file.
// This file stores boolean flags such as first_launch_done.
// Override: KEYLATCH_DAEMON_STATE_PATH
func DaemonState(env Lookup) string {
	if v := env("KEYLATCH_DAEMON_STATE_PATH"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(env), "daemon-state.json")
}

// UnsafeMode is returned by AssertSafeModes when the file or directory has
// insecure permissions.
type UnsafeMode struct {
	Path string
	Got  os.FileMode
	Want string // human-readable description of expected mode(s)
}

func (e *UnsafeMode) Error() string {
	return fmt.Sprintf("unsafe mode on %q: got %04o, want %s", e.Path, e.Got, e.Want)
}

// PathNotFound is returned by AssertSafeModes when the path does not exist.
type PathNotFound struct {
	Path string
}

func (e *PathNotFound) Error() string {
	return fmt.Sprintf("path not found: %q", e.Path)
}

// AssertSafeModes verifies that p has mode 0o600 (regular file) or 0o700
// (directory) and is owned by the current uid.
//
// Returns *PathNotFound if the path does not exist, *UnsafeMode if the mode
// or owner is incorrect.
func AssertSafeModes(p string) error {
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &PathNotFound{Path: p}
		}
		return fmt.Errorf("stat %q: %w", p, err)
	}

	mode := info.Mode()
	perm := mode.Perm()

	// Windows NTFS does not enforce Unix permission bits — os.MkdirAll(p, 0o700)
	// creates directories reported as 0777 by Stat. Skip the mode check on Windows.
	if runtime.GOOS != "windows" {
		if mode.IsDir() {
			if perm != 0o700 {
				return &UnsafeMode{Path: p, Got: perm, Want: "0700 (directory)"}
			}
		} else {
			if perm != 0o600 {
				return &UnsafeMode{Path: p, Got: perm, Want: "0600 (file)"}
			}
		}
	}

	// Check uid ownership via syscall.
	if err := assertOwner(p, info); err != nil {
		return err
	}

	return nil
}

// assertOwner checks that the path is owned by the current process uid.
// Platform-specific implementation lives in paths_unix.go / paths_windows.go.
