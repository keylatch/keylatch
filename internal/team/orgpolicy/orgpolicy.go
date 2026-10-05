// Package orgpolicy implements org policy bundle management.
//
// Security invariants:
// - org AllowedEnvelope is a hard upper bound.
// - Ed25519 signature by the pinned org key required on all bundles.
// - Monotonic version — old bundles cannot be reinstalled.
// - Expired bundles are rejected on install and not returned by Active.
package orgpolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/team/bundlesig"
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
	ErrKeyMismatch      = errors.New("org policy key differs from the key pinned by the first install")
	ErrOrgDeny          = errors.New("request denied by org policy baseline")
	// ErrActiveUntrusted means an installed bundle exists but cannot be
	// trusted: it does not parse, no key is pinned, or its signature does
	// not verify against the pinned key. Callers must deny rather than run
	// without the org ceiling.
	ErrActiveUntrusted = errors.New("installed org policy bundle cannot be trusted")
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

// trustedKeyPath holds the org policy public key pinned by the first install.
func trustedKeyPath() string {
	return filepath.Join(bundleDir(), "trusted-key.pub")
}

const signingDomain = "keylatch/org-policy/v2"

func signedMessage(b *OrgBundle) []byte {
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
	data, _ := json.Marshal(canonical{
		SchemaVersion:   b.SchemaVersion,
		BundleID:        b.BundleID,
		Version:         b.Version,
		TeamID:          b.TeamID,
		Issuer:          b.Issuer,
		IssuedAt:        b.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:       b.ExpiresAt.UTC().Format(time.RFC3339Nano),
		AllowedEnvelope: b.AllowedEnvelope,
		BaselineDeny:    b.BaselineDeny,
	})
	return bundlesig.Message(signingDomain, string(data))
}

func checkSignature(b *OrgBundle, pub ed25519.PublicKey) error {
	err := bundlesig.Verify(pub, signedMessage(b), b.Signature)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bundlesig.ErrUnsigned), errors.Is(err, bundlesig.ErrLegacySignature):
		return fmt.Errorf("%w: %w; ask the org policy issuer to re-sign it with the org's Ed25519 key", ErrSignatureInvalid, err)
	default:
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
}

func readBundle(path string) (*OrgBundle, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller-chosen bundle file
	if err != nil {
		return nil, fmt.Errorf("orgpolicy: read bundle %q: %w", path, err)
	}
	var b OrgBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("orgpolicy: parse bundle: %w", err)
	}
	return &b, nil
}

// Verify checks a bundle file's signature against pubKey (base64 Ed25519)
// and its expiry.
func Verify(_ context.Context, bundlePath string, pubKey string) error {
	pub, err := bundlesig.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("orgpolicy: %w", err)
	}
	b, err := readBundle(bundlePath)
	if err != nil {
		return err
	}
	if err := checkSignature(b, pub); err != nil {
		return err
	}
	if time.Now().After(b.ExpiresAt) {
		return ErrBundleExpired
	}
	return nil
}

// Install verifies the bundle against pubKey (base64 Ed25519), enforces a
// monotonic version and writes it atomically. The first install pins
// pubKey; later installs must use the same key.
func Install(ctx context.Context, bundlePath string, pubKey string) error {
	pub, err := bundlesig.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("orgpolicy: %w", err)
	}
	pinned, err := pinnedKey()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if pinned != nil && !pinned.Equal(pub) {
		return ErrKeyMismatch
	}

	b, err := readBundle(bundlePath)
	if err != nil {
		return err
	}
	if err := checkSignature(b, pub); err != nil {
		return err
	}
	if time.Now().After(b.ExpiresAt) {
		return ErrBundleExpired
	}
	if existing, err := Active(ctx); err == nil && existing != nil && b.Version <= existing.Version {
		return ErrBundleVersionLow
	}

	dir := bundleDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("orgpolicy: mkdir: %w", err)
	}
	if pinned == nil {
		if err := writeAtomic(trustedKeyPath(), []byte(bundlesig.EncodePublicKey(pub)+"\n")); err != nil {
			return err
		}
	}
	out, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return fmt.Errorf("orgpolicy: marshal: %w", err)
	}
	if err := writeAtomic(activeBundlePath(), out); err != nil {
		return err
	}

	mu.Lock()
	activeBundle = b
	mu.Unlock()
	return nil
}

func pinnedKey() (ed25519.PublicKey, error) {
	data, err := os.ReadFile(trustedKeyPath())
	if err != nil {
		return nil, err
	}
	pub, err := bundlesig.ParsePublicKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("orgpolicy: pinned key %q: %w", trustedKeyPath(), err)
	}
	return pub, nil
}

func writeAtomic(dest string, data []byte) error {
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("orgpolicy: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("orgpolicy: rename: %w", err)
	}
	return nil
}

// Active returns the currently installed OrgBundle. It returns nil and no
// error when no bundle is installed or the installed one has expired, and
// ErrActiveUntrusted when a bundle is installed but cannot be verified.
// Entire function runs under a single write lock to avoid lock-upgrade races.
func Active(_ context.Context) (*OrgBundle, error) {
	mu.Lock()
	defer mu.Unlock()

	if activeBundle != nil {
		if time.Now().After(activeBundle.ExpiresAt) {
			activeBundle = nil
			return nil, nil
		}
		b := *activeBundle
		return &b, nil
	}

	data, err := os.ReadFile(activeBundlePath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrActiveUntrusted, err)
	}
	var b OrgBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrActiveUntrusted, err)
	}
	pub, err := pinnedKey()
	if err != nil {
		return nil, fmt.Errorf("%w: no pinned key: %w", ErrActiveUntrusted, err)
	}
	if err := checkSignature(&b, pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrActiveUntrusted, err)
	}
	if time.Now().After(b.ExpiresAt) {
		return nil, nil
	}
	activeBundle = &b
	return &b, nil
}

// SignBundle sets b.Signature using the org's Ed25519 private key.
func SignBundle(b *OrgBundle, priv ed25519.PrivateKey) {
	b.Signature = bundlesig.Sign(priv, signedMessage(b))
}

// ResetForTest clears the in-memory active bundle cache.
// Only for use in tests — allows tests to isolate global state.
func ResetForTest() {
	mu.Lock()
	activeBundle = nil
	mu.Unlock()
}
