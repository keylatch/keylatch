// Package sandbox implements the direct_classic_sandboxed runtime driver.
// On Linux it uses bwrap; on macOS it uses sandbox-exec.
//
// Security invariants:
// - Executable hash is verified before execution.
// - ~/.keylatch is never accessible inside the sandbox.
// - Child env only receives explicit inject vars (inherit: false).
// - No shell string construction — all subprocess calls use argv slices.
// - Feature flag "direct_classic_sandboxed" must be true in ExecRequest.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	// Deny lists additional filesystem paths that must never be accessible
	// inside the sandbox (beyond the always-denied ~/.keylatch).
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

// ErrForbiddenMount is returned when a bind mount targets ~/.keylatch.
var ErrForbiddenMount = fmt.Errorf("sandbox: bind mount targeting ~/.keylatch is forbidden")

// ErrHashMismatch is returned when the executable's SHA-256 does not match.
var ErrHashMismatch = fmt.Errorf("sandbox: executable hash mismatch")

// ErrFeatureFlagRequired is returned when the "direct_classic_sandboxed"
// feature flag is absent from the ExecRequest.
var ErrFeatureFlagRequired = fmt.Errorf("sandbox: direct_classic_sandboxed feature flag must be true")

// LoadManifest loads a SandboxManifest from
// ~/.keylatch/sandbox-profiles/<profileID>.yaml.
//
// profileID must not contain path separators or be a relative path reference
// (e.g. ".." or ".") to prevent path traversal attacks (C3).
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
// Uses HashExecutable for streaming IO to avoid loading large binaries into RAM (C2).
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

// ValidateBindMounts checks that no bind mount targets ~/.keylatch.
// Returns ErrForbiddenMount on violation.
//
// S5: if homeDir is non-empty it is used directly, avoiding a redundant
// os.UserHomeDir() call when the caller already holds the value.
func ValidateBindMounts(m *SandboxManifest) error {
	return validateBindMountsWithHome(m, "")
}

// validateBindMountsWithHome is the internal variant that accepts a pre-computed
// homeDir. Pass "" to derive it via os.UserHomeDir() (S5).
func validateBindMountsWithHome(m *SandboxManifest, homeDir string) error {
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("sandbox: get home dir: %w", err)
		}
	}
	keylatchDir := filepath.Join(homeDir, ".keylatch")
	for _, bm := range m.BindMounts {
		src := filepath.Clean(bm.Src)
		if src == keylatchDir || isUnder(src, keylatchDir) {
			return fmt.Errorf("%w: %q", ErrForbiddenMount, bm.Src)
		}
		dst := filepath.Clean(bm.Dest)
		if dst == keylatchDir || isUnder(dst, keylatchDir) {
			return fmt.Errorf("%w: %q", ErrForbiddenMount, bm.Dest)
		}
	}
	return nil
}

// isUnder returns true if path is under (or equal to) dir.
func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.IsAbs(rel) && (rel == "" || rel[0] != '.')
}
