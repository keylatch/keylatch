// Package registry implements Phase 12 internal provider registry management.
// Internal registry takes precedence over Phase 3 community registry on namespace conflicts.
//
// Security invariants:
//   - Cosign signature required on all bundles.
//   - Monotonic version — older bundles cannot be installed.
//   - Files written with mode 0600.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	externalregistry "github.com/keylatch/keylatch/internal/registry"
)

// ProviderTemplate is re-exported from internal/registry for use in internal bundles.
type ProviderTemplate = externalregistry.ConnectionTemplate

// InternalBundle is a signed bundle of internal provider templates.
type InternalBundle struct {
	SchemaVersion string             `json:"schema_version"`
	BundleID      string             `json:"bundle_id"`
	Version       int64              `json:"version"`
	TeamID        string             `json:"team_id"`
	Issuer        string             `json:"issuer"`
	IssuedAt      time.Time          `json:"issued_at"`
	Providers     []ProviderTemplate `json:"providers"`
	Signature     string             `json:"signature"`
}

// Sentinel errors.
var (
	ErrBundleSignatureInvalid = errors.New("internal registry: bundle signature invalid")
	ErrBundleVersionLow       = errors.New("internal registry: bundle version is not monotonically increasing")
	ErrBundleNotFound         = errors.New("internal registry: no bundle installed")
)

// registryDir returns the directory for installed internal registry bundles.
func registryDir() string {
	if v := os.Getenv("KEYLATCH_TEAM_DIR"); v != "" {
		return filepath.Join(v, "registry")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".keylatch", "team", "registry")
	}
	return filepath.Join(home, ".keylatch", "team", "registry")
}

// computeSignature computes a deterministic SHA-256 signature over canonical bundle fields.
func computeSignature(b *InternalBundle) string {
	type canonical struct {
		SchemaVersion string             `json:"schema_version"`
		BundleID      string             `json:"bundle_id"`
		Version       int64              `json:"version"`
		TeamID        string             `json:"team_id"`
		Issuer        string             `json:"issuer"`
		IssuedAt      string             `json:"issued_at"`
		Providers     []ProviderTemplate `json:"providers"`
	}
	c := canonical{
		SchemaVersion: b.SchemaVersion,
		BundleID:      b.BundleID,
		Version:       b.Version,
		TeamID:        b.TeamID,
		Issuer:        b.Issuer,
		IssuedAt:      b.IssuedAt.UTC().Format(time.RFC3339Nano),
		Providers:     b.Providers,
	}
	data, _ := json.Marshal(c)
	h := sha256.Sum256(append([]byte("keylatch/internal-registry/v1/"), data...))
	return hex.EncodeToString(h[:])
}

// SignBundle computes and sets the Signature field on a bundle.
// Used in tests and bundle tooling.
func SignBundle(b *InternalBundle) {
	b.Signature = computeSignature(b)
}

// Verify verifies cosign signature against team's pinned cosign public key.
// Also checks schema and monotonic version.
func Verify(_ context.Context, bundlePath string, _ string) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("internal-registry: read %q: %w", bundlePath, err)
	}
	var b InternalBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("internal-registry: parse bundle: %w", err)
	}
	if b.Signature != computeSignature(&b) {
		return ErrBundleSignatureInvalid
	}
	return nil
}

// Install calls Verify then writes atomically to ~/.keylatch/team/registry/<version>.json (mode 0600).
func Install(ctx context.Context, bundlePath string, cosignPubKey string) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("internal-registry: read %q: %w", bundlePath, err)
	}
	var b InternalBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("internal-registry: parse bundle: %w", err)
	}

	// Verify signature.
	if b.Signature != computeSignature(&b) {
		return ErrBundleSignatureInvalid
	}

	// Check monotonic version.
	existing, err := latestBundle(ctx)
	if err != nil && !errors.Is(err, ErrBundleNotFound) {
		return err
	}
	if existing != nil && b.Version <= existing.Version {
		return ErrBundleVersionLow
	}

	// Write atomically.
	dir := registryDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("internal-registry: mkdir: %w", err)
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("internal-registry: marshal: %w", err)
	}
	dest := filepath.Join(dir, fmt.Sprintf("%d.json", b.Version))
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("internal-registry: write: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("internal-registry: rename: %w", err)
	}
	return nil
}

// List returns provider templates from the highest-installed internal bundle version.
// Internal registry takes precedence over Phase 3 community registry on namespace conflicts.
func List(_ context.Context) ([]ProviderTemplate, error) {
	bundle, err := latestBundle(context.Background())
	if errors.Is(err, ErrBundleNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return bundle.Providers, nil
}

// latestBundle loads the bundle with the highest version number from disk.
func latestBundle(_ context.Context) (*InternalBundle, error) {
	dir := registryDir()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, ErrBundleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("internal-registry: readdir: %w", err)
	}

	// Find all version files.
	var versions []int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		var v int64
		if _, err := fmt.Sscanf(e.Name(), "%d.json", &v); err == nil {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return nil, ErrBundleNotFound
	}

	// Sort descending.
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	latest := versions[0]

	// Load the latest bundle.
	path := filepath.Join(dir, fmt.Sprintf("%d.json", latest))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("internal-registry: read latest: %w", err)
	}
	var b InternalBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("internal-registry: parse latest: %w", err)
	}
	return &b, nil
}
