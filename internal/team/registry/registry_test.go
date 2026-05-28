package registry_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	teamregistry "github.com/keylatch/keylatch/internal/team/registry"
)

func newTestBundle(version int64, providers []teamregistry.ProviderTemplate) *teamregistry.InternalBundle {
	b := &teamregistry.InternalBundle{
		SchemaVersion: "1",
		BundleID:      "test-bundle",
		Version:       version,
		TeamID:        "team-test",
		Issuer:        "test-issuer",
		IssuedAt:      time.Now().UTC(),
		Providers:     providers,
	}
	teamregistry.SignBundle(b)
	return b
}

func writeBundleFile(t *testing.T, dir string, b *teamregistry.InternalBundle) string {
	t.Helper()
	data, _ := json.MarshalIndent(b, "", "  ")
	path := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(path, data, 0o600)
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

func TestInstall_ValidBundle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	providers := []teamregistry.ProviderTemplate{newProvider("internal-tool")}
	b := newTestBundle(1, providers)
	bundlePath := writeBundleFile(t, dir, b)

	ctx := context.Background()
	if err := teamregistry.Install(ctx, bundlePath, "cosign-pub"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	listed, err := teamregistry.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("expected 1 provider, got %d", len(listed))
	}
	if listed[0].Provider != "internal-tool" {
		t.Errorf("Provider = %q, want internal-tool", listed[0].Provider)
	}
}

func TestInstall_InvalidSignature(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	b := newTestBundle(1, nil)
	b.Signature = "tampered"
	bundlePath := writeBundleFile(t, dir, b)

	err := teamregistry.Install(context.Background(), bundlePath, "cosign-pub")
	if err != teamregistry.ErrBundleSignatureInvalid {
		t.Errorf("Install with bad sig: got %v, want ErrBundleSignatureInvalid", err)
	}
}

func TestInstall_MonotonicVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()

	// Install version 2.
	b2 := newTestBundle(2, nil)
	p2 := writeBundleFile(t, dir, b2)
	if err := teamregistry.Install(ctx, p2, "cosign-pub"); err != nil {
		t.Fatalf("Install v2: %v", err)
	}

	// Attempt to install version 1 (older) — should fail.
	b1 := newTestBundle(1, nil)
	p1 := filepath.Join(dir, "bundle-old.json")
	data, _ := json.MarshalIndent(b1, "", "  ")
	_ = os.WriteFile(p1, data, 0o600)

	err := teamregistry.Install(ctx, p1, "cosign-pub")
	if err != teamregistry.ErrBundleVersionLow {
		t.Errorf("Install old version: got %v, want ErrBundleVersionLow", err)
	}
}

func TestVerify_ValidBundle(t *testing.T) {
	dir := t.TempDir()
	b := newTestBundle(1, nil)
	bundlePath := writeBundleFile(t, dir, b)

	if err := teamregistry.Verify(context.Background(), bundlePath, "cosign-pub"); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_TamperedBundle(t *testing.T) {
	dir := t.TempDir()
	b := newTestBundle(1, []teamregistry.ProviderTemplate{newProvider("tool")})
	b.Signature = "tampered-signature"
	bundlePath := writeBundleFile(t, dir, b)

	err := teamregistry.Verify(context.Background(), bundlePath, "cosign-pub")
	if err != teamregistry.ErrBundleSignatureInvalid {
		t.Errorf("Verify tampered: got %v, want ErrBundleSignatureInvalid", err)
	}
}
