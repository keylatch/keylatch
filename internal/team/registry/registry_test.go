package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/team/bundlesig"
	teamregistry "github.com/keylatch/keylatch/internal/team/registry"
)

type teamKey struct {
	pub  string
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) teamKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return teamKey{pub: bundlesig.EncodePublicKey(pub), priv: priv}
}

func newTestBundle(version int64, providers []teamregistry.ProviderTemplate) *teamregistry.InternalBundle {
	return &teamregistry.InternalBundle{
		SchemaVersion: "1",
		BundleID:      "test-bundle",
		Version:       version,
		TeamID:        "team-test",
		Issuer:        "test-issuer",
		IssuedAt:      time.Now().UTC(),
		Providers:     providers,
	}
}

func writeBundleFile(t *testing.T, dir, name string, b *teamregistry.InternalBundle) string {
	t.Helper()
	data, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newProvider(slug string) teamregistry.ProviderTemplate {
	return registry.ConnectionTemplate{
		Provider:     slug,
		DisplayName:  slug,
		Category:     "internal",
		SecretFields: []registry.SecretField{},
		AuthFlow:     registry.AuthAPIKey,
		TrustLevel:   registry.TrustInternal,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
		},
		TestStrategy: registry.TestStrategy{},
	}
}

// legacyDigest reproduces the unkeyed SHA-256 "signature" older releases
// wrote, which anyone can recompute over edited content.
func legacyDigest(b *teamregistry.InternalBundle) string {
	type canonical struct {
		SchemaVersion string                          `json:"schema_version"`
		BundleID      string                          `json:"bundle_id"`
		Version       int64                           `json:"version"`
		TeamID        string                          `json:"team_id"`
		Issuer        string                          `json:"issuer"`
		IssuedAt      string                          `json:"issued_at"`
		Providers     []teamregistry.ProviderTemplate `json:"providers"`
	}
	data, _ := json.Marshal(canonical{
		b.SchemaVersion, b.BundleID, b.Version, b.TeamID, b.Issuer,
		b.IssuedAt.UTC().Format(time.RFC3339Nano), b.Providers,
	})
	h := sha256.Sum256(append([]byte("keylatch/internal-registry/v1/"), data...))
	return hex.EncodeToString(h[:])
}

func TestInstallAcceptsBundleSignedByTrustedKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	key := newKey(t)

	b := newTestBundle(1, []teamregistry.ProviderTemplate{newProvider("internal-tool")})
	teamregistry.SignBundle(b, key.priv)
	ctx := context.Background()
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "bundle.json", b), key.pub); err != nil {
		t.Fatalf("Install: %v", err)
	}

	listed, err := teamregistry.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 || listed[0].Provider != "internal-tool" {
		t.Fatalf("List = %+v, want internal-tool", listed)
	}
}

func TestInstallRejectsRecomputedLegacyDigest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	key := newKey(t)

	b := newTestBundle(1, []teamregistry.ProviderTemplate{newProvider("attacker-tool")})
	b.Signature = legacyDigest(b)
	err := teamregistry.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), key.pub)
	if !errors.Is(err, teamregistry.ErrBundleSignatureInvalid) || !errors.Is(err, bundlesig.ErrLegacySignature) {
		t.Fatalf("Install legacy bundle: got %v, want ErrBundleSignatureInvalid wrapping ErrLegacySignature", err)
	}
	if !strings.Contains(err.Error(), "re-sign") {
		t.Errorf("error %q does not say how to recover", err)
	}
}

func TestInstallRejectsUnsignedTamperedAndWrongKey(t *testing.T) {
	signer, trusted := newKey(t), newKey(t)

	unsigned := newTestBundle(1, nil)

	tampered := newTestBundle(1, []teamregistry.ProviderTemplate{newProvider("tool")})
	teamregistry.SignBundle(tampered, trusted.priv)
	tampered.Providers = append(tampered.Providers, newProvider("extra"))

	foreign := newTestBundle(1, nil)
	teamregistry.SignBundle(foreign, signer.priv)

	cases := []struct {
		name string
		b    *teamregistry.InternalBundle
		want error
	}{
		{"unsigned", unsigned, bundlesig.ErrUnsigned},
		{"tampered", tampered, bundlesig.ErrInvalidSignature},
		{"wrong key", foreign, bundlesig.ErrInvalidSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("KEYLATCH_TEAM_DIR", dir)
			err := teamregistry.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", tc.b), trusted.pub)
			if !errors.Is(err, teamregistry.ErrBundleSignatureInvalid) || !errors.Is(err, tc.want) {
				t.Fatalf("Install: got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestInstallRequiresTrustedKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	key := newKey(t)
	b := newTestBundle(1, nil)
	teamregistry.SignBundle(b, key.priv)

	err := teamregistry.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), "")
	if !errors.Is(err, bundlesig.ErrNoTrustedKey) {
		t.Fatalf("Install without key: got %v, want ErrNoTrustedKey", err)
	}
}

func TestInstallRejectsKeyDifferentFromPinned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	first, second := newKey(t), newKey(t)

	b1 := newTestBundle(1, nil)
	teamregistry.SignBundle(b1, first.priv)
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "b1.json", b1), first.pub); err != nil {
		t.Fatalf("Install first: %v", err)
	}
	b2 := newTestBundle(2, nil)
	teamregistry.SignBundle(b2, second.priv)
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "b2.json", b2), second.pub); !errors.Is(err, teamregistry.ErrKeyMismatch) {
		t.Fatalf("Install with a new key: got %v, want ErrKeyMismatch", err)
	}
}

func TestListRejectsInstalledBundleNotSignedByPinnedKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	key := newKey(t)

	b := newTestBundle(1, nil)
	teamregistry.SignBundle(b, key.priv)
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "bundle.json", b), key.pub); err != nil {
		t.Fatalf("Install: %v", err)
	}

	forged := newTestBundle(2, []teamregistry.ProviderTemplate{newProvider("attacker-tool")})
	forged.Signature = legacyDigest(forged)
	writeBundleFile(t, filepath.Join(dir, "registry"), "2.json", forged)

	if _, err := teamregistry.List(ctx); !errors.Is(err, teamregistry.ErrBundleSignatureInvalid) {
		t.Fatalf("List with forged bundle: got %v, want ErrBundleSignatureInvalid", err)
	}
}

func TestInstall_MonotonicVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	key := newKey(t)

	b2 := newTestBundle(2, nil)
	teamregistry.SignBundle(b2, key.priv)
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "b2.json", b2), key.pub); err != nil {
		t.Fatalf("Install v2: %v", err)
	}
	b1 := newTestBundle(1, nil)
	teamregistry.SignBundle(b1, key.priv)
	if err := teamregistry.Install(ctx, writeBundleFile(t, dir, "b1.json", b1), key.pub); !errors.Is(err, teamregistry.ErrBundleVersionLow) {
		t.Errorf("Install old version: got %v, want ErrBundleVersionLow", err)
	}
}

func TestVerify(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	b := newTestBundle(1, []teamregistry.ProviderTemplate{newProvider("tool")})
	teamregistry.SignBundle(b, key.priv)
	path := writeBundleFile(t, dir, "bundle.json", b)

	if err := teamregistry.Verify(context.Background(), path, key.pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
	b.Issuer = "someone-else"
	path = writeBundleFile(t, dir, "bundle.json", b)
	if err := teamregistry.Verify(context.Background(), path, key.pub); !errors.Is(err, teamregistry.ErrBundleSignatureInvalid) {
		t.Errorf("Verify tampered: got %v, want ErrBundleSignatureInvalid", err)
	}
}
