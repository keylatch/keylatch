package orgpolicy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/orgpolicy"
)

func newTestBundle(version int64, expiresIn time.Duration) *orgpolicy.OrgBundle {
	b := &orgpolicy.OrgBundle{
		SchemaVersion: "1",
		BundleID:      "bundle-" + time.Now().Format("20060102150405"),
		Version:       version,
		TeamID:        "team-test",
		Issuer:        "test-issuer",
		IssuedAt:      time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(expiresIn),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{
			MaxScope:    "full",
			AllowedEnvs: []string{"production", "staging", "development"},
		},
		BaselineDeny: []string{},
	}
	orgpolicy.SignBundle(b)
	return b
}

func writeBundleFile(t *testing.T, dir string, b *orgpolicy.OrgBundle) string {
	t.Helper()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestInstall_ValidBundle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	b := newTestBundle(1, 24*time.Hour)
	bundlePath := writeBundleFile(t, dir, b)

	ctx := context.Background()
	if err := orgpolicy.Install(ctx, bundlePath, "cosign-pub"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	active := orgpolicy.Active(ctx)
	if active == nil {
		t.Fatal("Active returned nil after Install")
	}
	if active.BundleID != b.BundleID {
		t.Errorf("BundleID = %q, want %q", active.BundleID, b.BundleID)
	}
}

func TestInstall_InvalidSignature(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	b := newTestBundle(1, 24*time.Hour)
	b.Signature = "bad-signature"
	bundlePath := writeBundleFile(t, dir, b)

	ctx := context.Background()
	err := orgpolicy.Install(ctx, bundlePath, "cosign-pub")
	if err != orgpolicy.ErrSignatureInvalid {
		t.Errorf("Install with bad sig: got %v, want ErrSignatureInvalid", err)
	}
}

func TestInstall_MonotonicVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	ctx := context.Background()

	// Install version 2.
	b2 := newTestBundle(2, 24*time.Hour)
	p2 := writeBundleFile(t, dir, b2)
	if err := orgpolicy.Install(ctx, p2, "cosign-pub"); err != nil {
		t.Fatalf("Install v2: %v", err)
	}

	// Attempt to install version 1 (older) — should fail.
	b1 := &orgpolicy.OrgBundle{
		SchemaVersion:   "1",
		BundleID:        "bundle-older",
		Version:         1,
		TeamID:          "team-test",
		Issuer:          "test-issuer",
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(24 * time.Hour),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
	}
	orgpolicy.SignBundle(b1)
	p1 := filepath.Join(dir, "bundle-old.json")
	data, _ := json.MarshalIndent(b1, "", "  ")
	_ = os.WriteFile(p1, data, 0o600)

	err := orgpolicy.Install(ctx, p1, "cosign-pub")
	if err != orgpolicy.ErrBundleVersionLow {
		t.Errorf("Install old version: got %v, want ErrBundleVersionLow", err)
	}
}

func TestActive_NilWhenNoBundleInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	ctx := context.Background()
	active := orgpolicy.Active(ctx)
	if active != nil {
		t.Errorf("Active = %+v, want nil when no bundle installed", active)
	}
}

func TestActive_NilWhenExpired(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	ctx := context.Background()

	// Write an already-expired bundle directly.
	b := &orgpolicy.OrgBundle{
		SchemaVersion:   "1",
		BundleID:        "expired-bundle",
		Version:         1,
		TeamID:          "team-test",
		Issuer:          "test-issuer",
		IssuedAt:        time.Now().UTC().Add(-48 * time.Hour),
		ExpiresAt:       time.Now().UTC().Add(-1 * time.Hour),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
	}
	orgpolicy.SignBundle(b)
	data, _ := json.MarshalIndent(b, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "active.json"), data, 0o600)

	active := orgpolicy.Active(ctx)
	if active != nil {
		t.Errorf("Active returned non-nil for expired bundle: %+v", active)
	}
}

func TestCompose_OrgDenyOverridesLocalAllow(t *testing.T) {
	ctx := context.Background()
	b := &orgpolicy.OrgBundle{
		BaselineDeny:    []string{"write"},
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	orgpolicy.SignBundle(b)

	local := orgpolicy.Decision{Allow: true, Reason: "local allow"}
	result := orgpolicy.Compose(ctx, b, local, "write", "production")
	if result.Allow {
		t.Error("expected deny when org baseline denies, got allow")
	}
}

func TestCompose_OrgAllowLocalDeny(t *testing.T) {
	ctx := context.Background()
	b := &orgpolicy.OrgBundle{
		BaselineDeny:    []string{},
		AllowedEnvelope: orgpolicy.AllowedEnvelope{AllowedEnvs: []string{"production"}},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	orgpolicy.SignBundle(b)

	local := orgpolicy.Decision{Allow: false, Reason: "local policy deny"}
	result := orgpolicy.Compose(ctx, b, local, "read", "production")
	if result.Allow {
		t.Error("expected deny (local-deny wins), got allow")
	}
}

func TestCompose_OrgAllowLocalNarrow(t *testing.T) {
	ctx := context.Background()
	b := &orgpolicy.OrgBundle{
		BaselineDeny:    []string{},
		AllowedEnvelope: orgpolicy.AllowedEnvelope{AllowedEnvs: []string{"production", "staging"}},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	orgpolicy.SignBundle(b)

	local := orgpolicy.Decision{Allow: true, Reason: "local allow"}
	result := orgpolicy.Compose(ctx, b, local, "read", "staging")
	if !result.Allow {
		t.Error("expected allow (org allows staging, local allows), got deny")
	}
}

func TestCompose_NilBundle_PassThrough(t *testing.T) {
	ctx := context.Background()
	local := orgpolicy.Decision{Allow: true, Reason: "local"}
	result := orgpolicy.Compose(ctx, nil, local, "write", "production")
	if !result.Allow {
		t.Error("nil bundle should pass through local decision")
	}
}
