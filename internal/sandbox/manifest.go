// Package sandbox implements the direct_classic_sandboxed runtime driver.
// On Linux it uses bwrap; on macOS it uses sandbox-exec.
//
// Security invariants:
// - Executable hash is verified before execution.
// - No bind mount may expose keylatch state, and every Deny path is masked.
// - Child env only receives explicit inject vars (inherit: false).
// - No shell string construction — all subprocess calls use argv slices.
// - Feature flag "direct_classic_sandboxed" must be true in ExecRequest.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"gopkg.in/yaml.v3"
)

// SandboxManifest describes a trusted sandbox execution profile.
// Profiles are stored at ~/.keylatch/sandbox-profiles/<profile-id>.yaml.
type SandboxManifest struct {
	// ProfileID is the unique profile identifier.
	ProfileID string `yaml:"profile_id"`
	// Executable is the absolute path to the trusted executable.
	Executable string `yaml:"executable"`
	// ExecHash is the expected SHA-256 hex digest of the executable binary.
	ExecHash string `yaml:"exec_hash"`
	// BindMounts lists filesystem paths to expose inside the sandbox.
	BindMounts []BindMount `yaml:"bind_mounts"`
	// Deny lists absolute paths, as seen inside the sandbox, that must never be
	// accessible there. The sandbox refuses to start if one cannot be masked.
	Deny []string `yaml:"deny,omitempty"`
	// EnvAllowlist lists env var names that pass through from the parent.
	EnvAllowlist []string `yaml:"env_allowlist"`
	// EnvInject holds env vars that are always injected regardless of allowlist.
	EnvInject map[string]string `yaml:"env_inject"`
}

// BindMount describes a single filesystem bind mount inside the sandbox.
type BindMount struct {
	// Src is the host filesystem path.
	Src string `yaml:"src"`
	// Dest is the path inside the sandbox.
	Dest string `yaml:"dest"`
	// RO indicates a read-only mount.
	RO bool `yaml:"ro"`
}

// ErrForbiddenMount is returned when a bind mount would expose keylatch state
// (configuration, vault, keyring, gateway or audit files) inside the sandbox.
var ErrForbiddenMount = fmt.Errorf("sandbox: bind mount exposing keylatch state is forbidden")

// ErrDenyUnenforceable is returned when a manifest Deny entry cannot be
// masked inside the sandbox; the sandbox refuses to start rather than run
// with the path exposed.
var ErrDenyUnenforceable = fmt.Errorf("sandbox: deny path cannot be enforced")

// ErrHashMismatch is returned when the executable's SHA-256 does not match.
var ErrHashMismatch = fmt.Errorf("sandbox: executable hash mismatch")

// ErrFeatureFlagRequired is returned when the "direct_classic_sandboxed"
// feature flag is absent from the ExecRequest.
var ErrFeatureFlagRequired = fmt.Errorf("sandbox: direct_classic_sandboxed feature flag must be true")

// LoadManifest loads a SandboxManifest from
// ~/.keylatch/sandbox-profiles/<profileID>.yaml.
//
// profileID must not contain path separators or be a relative path reference
// (e.g. ".." or ".") to prevent path traversal attacks.
func LoadManifest(profileID string) (*SandboxManifest, error) {
	if profileID == "" || profileID == ".." || profileID == "." || strings.ContainsAny(profileID, "/\\") {
		return nil, fmt.Errorf("sandbox: invalid profile ID %q: must not contain path separators", profileID)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("sandbox: get home dir: %w", err)
	}
	path := filepath.Join(home, ".keylatch", "sandbox-profiles", profileID+".yaml")
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is constructed from profileID (validated caller input)
	if err != nil {
		return nil, fmt.Errorf("sandbox: read manifest %q: %w", path, err)
	}
	var m SandboxManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("sandbox: parse manifest %q: %w", path, err)
	}
	return &m, nil
}

// LoadManifestFromPath loads a SandboxManifest from an explicit path.
// Used by tests to avoid ~/.keylatch access.
func LoadManifestFromPath(path string) (*SandboxManifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: test helper — path is caller-supplied
	if err != nil {
		return nil, fmt.Errorf("sandbox: read manifest %q: %w", path, err)
	}
	var m SandboxManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("sandbox: parse manifest %q: %w", path, err)
	}
	return &m, nil
}

// VerifyExecHash streams the executable at m.Executable and verifies its
// SHA-256 matches m.ExecHash. Returns ErrHashMismatch on mismatch.
//
// Uses HashExecutable for streaming IO to avoid loading large binaries into RAM.
func VerifyExecHash(m *SandboxManifest) error {
	got, err := HashExecutable(m.Executable)
	if err != nil {
		return fmt.Errorf("sandbox: read executable for hash verify: %w", err)
	}
	if got != m.ExecHash {
		return fmt.Errorf("%w: want %s got %s", ErrHashMismatch, m.ExecHash, got)
	}
	return nil
}

// ValidateBindMounts checks that no bind mount exposes keylatch state.
// Returns ErrForbiddenMount on violation.
func ValidateBindMounts(m *SandboxManifest) error {
	return validateBindMountsWithHome(m, "")
}

// validateBindMountsWithHome is ValidateBindMounts with a pre-computed home
// directory; pass "" to derive it.
func validateBindMountsWithHome(m *SandboxManifest, homeDir string) error {
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("sandbox: get home dir: %w", err)
		}
	}
	return validateBindMounts(m, protectedPaths(homeDir, llmcontext.DefaultLookup))
}

// validateBindMounts rejects a mount whose source or destination is equal to,
// inside, or an ancestor of a protected path. An ancestor exposes everything
// below it, so binding $HOME or / is as forbidden as binding the config dir.
// Both the lexical and the symlink-resolved form of every path are compared.
func validateBindMounts(m *SandboxManifest, protected []string) error {
	var guarded []string
	for _, p := range protected {
		guarded = append(guarded, pathForms(p)...)
	}
	for _, bm := range m.BindMounts {
		for _, raw := range []string{bm.Src, bm.Dest} {
			if !filepath.IsAbs(raw) {
				return fmt.Errorf("%w: %q is not an absolute path", ErrForbiddenMount, raw)
			}
			for _, form := range pathForms(raw) {
				for _, g := range guarded {
					if isUnder(form, g) || isUnder(g, form) {
						return fmt.Errorf("%w: %q", ErrForbiddenMount, raw)
					}
				}
			}
		}
	}
	return nil
}

// protectedPaths lists every location that can hold keylatch state: the
// default directories of every platform plus the configured overrides.
func protectedPaths(homeDir string, env paths.Lookup) []string {
	out := []string{
		filepath.Join(homeDir, ".keylatch"),
		filepath.Join(homeDir, ".config", "keylatch"),
		filepath.Join(homeDir, "Library", "Application Support", "keylatch"),
	}
	if xdg := env("XDG_CONFIG_HOME"); xdg != "" {
		out = append(out, filepath.Join(xdg, "keylatch"))
	}
	for _, resolve := range []func(paths.Lookup) string{
		paths.ConfigDir, paths.Config, paths.Vault, paths.Audit, paths.AuditSalt,
		paths.Policy, paths.Grants, paths.GrantsDir, paths.GrantAccessorKey,
		paths.KeyringDir, paths.KeyringPath, paths.KeyringIdentityPath,
		paths.GatewayDir, paths.GatewaySigningKey, paths.GatewayTokens,
		paths.ApprovalsDir, paths.DaemonState,
	} {
		if p := resolve(env); filepath.IsAbs(p) {
			out = append(out, p)
		}
	}
	return out
}

// pathForms returns the cleaned path and, when it differs, the path with
// symlinks resolved in its longest existing prefix.
func pathForms(p string) []string {
	clean := filepath.Clean(p)
	if resolved := resolveExisting(clean); resolved != clean {
		return []string{clean, resolved}
	}
	return []string{clean}
}

// resolveExisting resolves symlinks in the longest existing prefix of p and
// appends the remaining components unchanged.
func resolveExisting(p string) string {
	rest := ""
	for cur := p; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// isUnder reports whether path is dir or lies inside it.
func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
