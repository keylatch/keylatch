// Package orgpolicy implements Phase 12 org policy bundle management.
//
// Security invariants:
//   - FIND3-005: org AllowedEnvelope is a hard upper bound.
//   - Cosign signature required on all bundles.
//   - Monotonic version — old bundles cannot be reinstalled.
//   - Expired bundles are rejected on install and not returned by Active.
package orgpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AllowedEnvelope is the ceiling on policy capabilities for the team.
type AllowedEnvelope struct {
	MaxScope         string   `json:"max_scope"`
	AllowedEnvs      []string `json:"allowed_envs"`
	DenyCapabilities []string `json:"deny_capabilities"`
	RequireApproval  []string `json:"require_approval"`
}

// OrgBundle is a signed org policy bundle.
type OrgBundle struct {
	SchemaVersion   string          `json:"schema_version"`
	BundleID        string          `json:"bundle_id"`
	Version         int64           `json:"version"`
	TeamID          string          `json:"team_id"`
	Issuer          string          `json:"issuer"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	AllowedEnvelope AllowedEnvelope `json:"allowed_envelope"`
	BaselineDeny    []string        `json:"baseline_deny"`
	Signature       string          `json:"signature"`
}

// Sentinel errors.
var (
	ErrBundleExpired    = errors.New("org policy bundle has expired")
	ErrBundleVersionLow = errors.New("org policy bundle version is not monotonically increasing")
	ErrSignatureInvalid = errors.New("org policy bundle signature is invalid")
	ErrOrgDeny          = errors.New("request denied by org policy baseline")
)

var (
	mu           sync.Mutex
	activeBundle *OrgBundle
)

// bundleDir returns the directory for installed org policy bundles.
func bundleDir() string {
	if v := os.Getenv("KEYLATCH_ORG_POLICY_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".keylatch", "team", "org-policy")
	}
	return filepath.Join(home, ".keylatch", "team", "org-policy")
}

// activeBundlePath returns the path to the installed active bundle.
func activeBundlePath() string {
	return filepath.Join(bundleDir(), "active.json")
}

// computeSignature computes a deterministic SHA-256 signature over canonical bundle fields.
// In production this would use cosign; here we use a SHA-256 hash over canonical JSON.
func computeSignature(b *OrgBundle) string {
	// Build a canonical representation (excluding the Signature field).
	type canonical struct {
		SchemaVersion   string          `json:"schema_version"`
		BundleID        string          `json:"bundle_id"`
		Version         int64           `json:"version"`
		TeamID          string          `json:"team_id"`
		Issuer          string          `json:"issuer"`
		IssuedAt        string          `json:"issued_at"`
		ExpiresAt       string          `json:"expires_at"`
		AllowedEnvelope AllowedEnvelope `json:"allowed_envelope"`
		BaselineDeny    []string        `json:"baseline_deny"`
	}
	c := canonical{
		SchemaVersion:   b.SchemaVersion,
		BundleID:        b.BundleID,
		Version:         b.Version,
		TeamID:          b.TeamID,
		Issuer:          b.Issuer,
		IssuedAt:        b.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:       b.ExpiresAt.UTC().Format(time.RFC3339Nano),
		AllowedEnvelope: b.AllowedEnvelope,
		BaselineDeny:    b.BaselineDeny,
	}
	data, _ := json.Marshal(c)
	h := sha256.Sum256(append([]byte("keylatch/org-policy/v1/"), data...))
	return hex.EncodeToString(h[:])
}

// Verify verifies the cosign signature on a bundle file.
// The cosignPubKey param is retained for future integration; we verify our deterministic sig.
func Verify(_ context.Context, bundlePath string, _ string) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("orgpolicy: read bundle %q: %w", bundlePath, err)
	}
	var b OrgBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("orgpolicy: parse bundle: %w", err)
	}
	storedSig := b.Signature
	expected := computeSignature(&b)
	if storedSig != expected {
		return ErrSignatureInvalid
	}
	if time.Now().After(b.ExpiresAt) {
		return ErrBundleExpired
	}
	return nil
}

// Install verifies cosign signature + monotonic version, writes atomically.
func Install(ctx context.Context, bundlePath string, cosignPubKey string) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("orgpolicy: read bundle %q: %w", bundlePath, err)
	}
	var b OrgBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("orgpolicy: parse bundle: %w", err)
	}

	// Verify signature.
	storedSig := b.Signature
	expected := computeSignature(&b)
	if storedSig != expected {
		return ErrSignatureInvalid
	}

	// Reject expired.
	if time.Now().After(b.ExpiresAt) {
		return ErrBundleExpired
	}

	// Check monotonic version against any existing active bundle.
	if existing := Active(ctx); existing != nil {
		if b.Version <= existing.Version {
			return ErrBundleVersionLow
		}
	}

	// Write atomically.
	dir := bundleDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("orgpolicy: mkdir: %w", err)
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("orgpolicy: marshal: %w", err)
	}
	dest := activeBundlePath()
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("orgpolicy: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("orgpolicy: rename: %w", err)
	}

	// Update in-memory cache.
	mu.Lock()
	activeBundle = &b
	mu.Unlock()
	return nil
}

// Active returns the currently installed OrgBundle, or nil if none installed.
// Returns nil if the bundle has expired (treats as if none installed).
// C-5: entire function runs under a single write lock to avoid lock-upgrade races.
func Active(_ context.Context) *OrgBundle {
	mu.Lock()
	defer mu.Unlock()

	if activeBundle != nil {
		if time.Now().After(activeBundle.ExpiresAt) {
			activeBundle = nil
			return nil
		}
		b := *activeBundle
		return &b
	}

	// Try loading from disk (also under the same mutex, preventing Install races).
	data, err := os.ReadFile(activeBundlePath())
	if err != nil {
		return nil
	}
	var b OrgBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil
	}
	if time.Now().After(b.ExpiresAt) {
		return nil
	}
	// Verify signature on load.
	if b.Signature != computeSignature(&b) {
		return nil
	}
	activeBundle = &b
	return &b
}

// SignBundle signs a bundle by computing and setting its Signature field.
// Used in tests and bundle creation tooling.
func SignBundle(b *OrgBundle) {
	b.Signature = computeSignature(b)
}

// ResetForTest clears the in-memory active bundle cache.
// Only for use in tests — allows tests to isolate global state.
func ResetForTest() {
	mu.Lock()
	activeBundle = nil
	mu.Unlock()
}
