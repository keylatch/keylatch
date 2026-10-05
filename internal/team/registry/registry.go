// Package registry implements internal provider registry management.
// Internal registry takes precedence over community registry on namespace conflicts.
//
// Security invariants:
// - Ed25519 signature by the pinned team key required on all bundles.
// - Monotonic version — older bundles cannot be installed.
// - Files written with mode 0600.
package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	externalregistry "github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/team/bundlesig"
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
	ErrKeyMismatch            = errors.New("internal registry: key differs from the key pinned by the first install")
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

func trustedKeyPath() string {
	return filepath.Join(registryDir(), "trusted-key.pub")
}

const signingDomain = "keylatch/internal-registry/v2"

func signedMessage(b *InternalBundle) []byte {
	type canonical struct {
		SchemaVersion string             `json:"schema_version"`
		BundleID      string             `json:"bundle_id"`
		Version       int64              `json:"version"`
		TeamID        string             `json:"team_id"`
		Issuer        string             `json:"issuer"`
		IssuedAt      string             `json:"issued_at"`
		Providers     []ProviderTemplate `json:"providers"`
	}
	data, _ := json.Marshal(canonical{
		SchemaVersion: b.SchemaVersion,
		BundleID:      b.BundleID,
		Version:       b.Version,
		TeamID:        b.TeamID,
		Issuer:        b.Issuer,
		IssuedAt:      b.IssuedAt.UTC().Format(time.RFC3339Nano),
		Providers:     b.Providers,
	})
	return bundlesig.Message(signingDomain, string(data))
}

func checkSignature(b *InternalBundle, pub ed25519.PublicKey) error {
	err := bundlesig.Verify(pub, signedMessage(b), b.Signature)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bundlesig.ErrUnsigned), errors.Is(err, bundlesig.ErrLegacySignature):
		return fmt.Errorf("%w: %w; ask the registry issuer to re-sign it with the team's Ed25519 key", ErrBundleSignatureInvalid, err)
	default:
		return fmt.Errorf("%w: %w", ErrBundleSignatureInvalid, err)
	}
}

// SignBundle sets b.Signature using the team's Ed25519 private key.
func SignBundle(b *InternalBundle, priv ed25519.PrivateKey) {
	b.Signature = bundlesig.Sign(priv, signedMessage(b))
}

func readBundle(path string) (*InternalBundle, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller-chosen or registry-owned bundle file
	if err != nil {
		return nil, fmt.Errorf("internal-registry: read %q: %w", path, err)
	}
	var b InternalBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("internal-registry: parse bundle: %w", err)
	}
	return &b, nil
}

// Verify checks a bundle file's signature against pubKey (base64 Ed25519).
func Verify(_ context.Context, bundlePath string, pubKey string) error {
	pub, err := bundlesig.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("internal-registry: %w", err)
	}
	b, err := readBundle(bundlePath)
	if err != nil {
		return err
	}
	return checkSignature(b, pub)
}

// Install verifies the bundle against pubKey (base64 Ed25519), enforces a
// monotonic version and writes it to <registry dir>/<version>.json (0600).
// The first install pins pubKey; later installs must use the same key.
func Install(_ context.Context, bundlePath string, pubKey string) error {
	pub, err := bundlesig.ParsePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("internal-registry: %w", err)
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

	latest, err := latestVersion()
	if err != nil && !errors.Is(err, ErrBundleNotFound) {
		return err
	}
	if err == nil && b.Version <= latest {
		return ErrBundleVersionLow
	}

	dir := registryDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("internal-registry: mkdir: %w", err)
	}
	if pinned == nil {
		if err := writeAtomic(trustedKeyPath(), []byte(bundlesig.EncodePublicKey(pub)+"\n")); err != nil {
			return err
		}
	}
	out, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return fmt.Errorf("internal-registry: marshal: %w", err)
	}
	return writeAtomic(filepath.Join(dir, fmt.Sprintf("%d.json", b.Version)), out)
}

func pinnedKey() (ed25519.PublicKey, error) {
	data, err := os.ReadFile(trustedKeyPath())
	if err != nil {
		return nil, err
	}
	pub, err := bundlesig.ParsePublicKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("internal-registry: pinned key %q: %w", trustedKeyPath(), err)
	}
	return pub, nil
}

func writeAtomic(dest string, data []byte) error {
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
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
// Internal registry takes precedence over community registry on namespace conflicts.
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

// latestVersion returns the highest installed bundle version.
func latestVersion() (int64, error) {
	entries, err := os.ReadDir(registryDir())
	if os.IsNotExist(err) {
		return 0, ErrBundleNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("internal-registry: readdir: %w", err)
	}
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
		return 0, ErrBundleNotFound
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	return versions[0], nil
}

// latestBundle loads the highest installed bundle and verifies it against
// the pinned key.
func latestBundle(_ context.Context) (*InternalBundle, error) {
	latest, err := latestVersion()
	if err != nil {
		return nil, err
	}
	pub, err := pinnedKey()
	if err != nil {
		return nil, fmt.Errorf("%w: no pinned registry key: %w", ErrBundleSignatureInvalid, err)
	}
	b, err := readBundle(filepath.Join(registryDir(), fmt.Sprintf("%d.json", latest)))
	if err != nil {
		return nil, err
	}
	if err := checkSignature(b, pub); err != nil {
		return nil, err
	}
	return b, nil
}
