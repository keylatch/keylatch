package orgpolicy_test

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

	"github.com/keylatch/keylatch/internal/team/bundlesig"
	"github.com/keylatch/keylatch/internal/team/orgpolicy"
)

type orgKey struct {
	pub  string
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) orgKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return orgKey{pub: bundlesig.EncodePublicKey(pub), priv: priv}
}

func setupDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	t.Cleanup(orgpolicy.ResetForTest)
	return dir
}

func newTestBundle(version int64, expiresIn time.Duration) *orgpolicy.OrgBundle {
	return &orgpolicy.OrgBundle{
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
		BaselineDeny: []string{"admin"},
	}
}

func writeBundleFile(t *testing.T, dir, name string, b *orgpolicy.OrgBundle) string {
	t.Helper()
	data, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// legacyDigest reproduces the unkeyed SHA-256 "signature" older releases
// wrote, which anyone can recompute over edited content.
func legacyDigest(b *orgpolicy.OrgBundle) string {
	type canonical struct {
		SchemaVersion   string                    `json:"schema_version"`
		BundleID        string                    `json:"bundle_id"`
		Version         int64                     `json:"version"`
		TeamID          string                    `json:"team_id"`
		Issuer          string                    `json:"issuer"`
		IssuedAt        string                    `json:"issued_at"`
		ExpiresAt       string                    `json:"expires_at"`
		AllowedEnvelope orgpolicy.AllowedEnvelope `json:"allowed_envelope"`
		BaselineDeny    []string                  `json:"baseline_deny"`
	}
	data, _ := json.Marshal(canonical{
		b.SchemaVersion, b.BundleID, b.Version, b.TeamID, b.Issuer,
		b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano),
		b.AllowedEnvelope, b.BaselineDeny,
	})
	h := sha256.Sum256(append([]byte("keylatch/org-policy/v1/"), data...))
	return hex.EncodeToString(h[:])
}

func TestInstallAcceptsBundleSignedByTrustedKey(t *testing.T) {
	dir := setupDir(t)
	key := newKey(t)
	b := newTestBundle(1, 24*time.Hour)
	orgpolicy.SignBundle(b, key.priv)

	ctx := context.Background()
	if err := orgpolicy.Verify(ctx, writeBundleFile(t, dir, "bundle.json", b), key.pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := orgpolicy.Install(ctx, filepath.Join(dir, "bundle.json"), key.pub); err != nil {
		t.Fatalf("Install: %v", err)
	}
	orgpolicy.ResetForTest()
	active := orgpolicy.Active(ctx)
	if active == nil || active.BundleID != b.BundleID {
		t.Fatalf("Active after reload = %+v, want bundle %q", active, b.BundleID)
	}
}

func TestInstallRejectsRecomputedLegacyDigest(t *testing.T) {
	dir := setupDir(t)
	key := newKey(t)
	b := newTestBundle(1, 24*time.Hour)
	b.BaselineDeny = nil
	b.Signature = legacyDigest(b)

	err := orgpolicy.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), key.pub)
	if !errors.Is(err, orgpolicy.ErrSignatureInvalid) || !errors.Is(err, bundlesig.ErrLegacySignature) {
		t.Fatalf("Install legacy bundle: got %v, want ErrSignatureInvalid wrapping ErrLegacySignature", err)
	}
	if !strings.Contains(err.Error(), "re-sign") {
		t.Errorf("error %q does not say how to recover", err)
	}
}

func TestInstallRejectsUnsignedBundle(t *testing.T) {
	dir := setupDir(t)
	key := newKey(t)
	err := orgpolicy.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", newTestBundle(1, time.Hour)), key.pub)
	if !errors.Is(err, bundlesig.ErrUnsigned) {
		t.Fatalf("Install unsigned: got %v, want ErrUnsigned", err)
	}
}

func TestInstallRejectsTamperedBundle(t *testing.T) {
	dir := setupDir(t)
	key := newKey(t)
	b := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b, key.priv)
	b.BaselineDeny = nil

	err := orgpolicy.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), key.pub)
	if !errors.Is(err, bundlesig.ErrInvalidSignature) {
		t.Fatalf("Install tampered: got %v, want ErrInvalidSignature", err)
	}
	if orgpolicy.Active(context.Background()) != nil {
		t.Error("tampered bundle became active")
	}
}

func TestInstallRejectsWrongKey(t *testing.T) {
	dir := setupDir(t)
	signer, trusted := newKey(t), newKey(t)
	b := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b, signer.priv)

	err := orgpolicy.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), trusted.pub)
	if !errors.Is(err, bundlesig.ErrInvalidSignature) {
		t.Fatalf("Install with wrong key: got %v, want ErrInvalidSignature", err)
	}
}

func TestInstallRequiresTrustedKey(t *testing.T) {
	dir := setupDir(t)
	key := newKey(t)
	b := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b, key.priv)

	err := orgpolicy.Install(context.Background(), writeBundleFile(t, dir, "bundle.json", b), "")
	if !errors.Is(err, bundlesig.ErrNoTrustedKey) {
		t.Fatalf("Install without key: got %v, want ErrNoTrustedKey", err)
	}
}

func TestInstallRejectsKeyDifferentFromPinned(t *testing.T) {
	dir := setupDir(t)
	ctx := context.Background()
	first, second := newKey(t), newKey(t)

	b1 := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b1, first.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "b1.json", b1), first.pub); err != nil {
		t.Fatalf("Install first: %v", err)
	}

	b2 := newTestBundle(2, time.Hour)
	orgpolicy.SignBundle(b2, second.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "b2.json", b2), second.pub); !errors.Is(err, orgpolicy.ErrKeyMismatch) {
		t.Fatalf("Install with a new key: got %v, want ErrKeyMismatch", err)
	}
}

func TestActiveIgnoresBundleNotSignedByPinnedKey(t *testing.T) {
	dir := setupDir(t)
	ctx := context.Background()
	pinned, other := newKey(t), newKey(t)

	b := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b, pinned.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "bundle.json", b), pinned.pub); err != nil {
		t.Fatalf("Install: %v", err)
	}

	forged := newTestBundle(2, time.Hour)
	forged.BaselineDeny = nil
	orgpolicy.SignBundle(forged, other.priv)
	writeBundleFile(t, dir, "active.json", forged)
	orgpolicy.ResetForTest()
	if got := orgpolicy.Active(ctx); got != nil {
		t.Fatalf("Active returned a bundle signed by an unpinned key: %+v", got)
	}

	forged.Signature = legacyDigest(forged)
	writeBundleFile(t, dir, "active.json", forged)
	orgpolicy.ResetForTest()
	if got := orgpolicy.Active(ctx); got != nil {
		t.Fatalf("Active returned a bundle with a legacy digest: %+v", got)
	}
}

func TestInstall_MonotonicVersion(t *testing.T) {
	dir := setupDir(t)
	ctx := context.Background()
	key := newKey(t)

	b2 := newTestBundle(2, 24*time.Hour)
	orgpolicy.SignBundle(b2, key.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "b2.json", b2), key.pub); err != nil {
		t.Fatalf("Install v2: %v", err)
	}

	b1 := newTestBundle(1, 24*time.Hour)
	orgpolicy.SignBundle(b1, key.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "b1.json", b1), key.pub); !errors.Is(err, orgpolicy.ErrBundleVersionLow) {
		t.Errorf("Install old version: got %v, want ErrBundleVersionLow", err)
	}
}

func TestActive_NilWhenNoBundleInstalled(t *testing.T) {
	setupDir(t)
	if active := orgpolicy.Active(context.Background()); active != nil {
		t.Errorf("Active = %+v, want nil when no bundle installed", active)
	}
}

func TestActive_NilWhenExpired(t *testing.T) {
	dir := setupDir(t)
	ctx := context.Background()
	key := newKey(t)

	b := newTestBundle(1, time.Hour)
	orgpolicy.SignBundle(b, key.priv)
	if err := orgpolicy.Install(ctx, writeBundleFile(t, dir, "bundle.json", b), key.pub); err != nil {
		t.Fatalf("Install: %v", err)
	}

	expired := newTestBundle(2, -time.Hour)
	orgpolicy.SignBundle(expired, key.priv)
	writeBundleFile(t, dir, "active.json", expired)
	orgpolicy.ResetForTest()
	if active := orgpolicy.Active(ctx); active != nil {
		t.Errorf("Active returned non-nil for expired bundle: %+v", active)
	}
}

func TestCompose_OrgDenyOverridesLocalAllow(t *testing.T) {
	b := &orgpolicy.OrgBundle{
		BaselineDeny:    []string{"write"},
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	local := orgpolicy.Decision{Allow: true, Reason: "local allow"}
	if orgpolicy.Compose(context.Background(), b, local, "write", "production").Allow {
		t.Error("expected deny when org baseline denies, got allow")
	}
}

func TestCompose_OrgAllowLocalDeny(t *testing.T) {
	b := &orgpolicy.OrgBundle{
		AllowedEnvelope: orgpolicy.AllowedEnvelope{AllowedEnvs: []string{"production"}},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	local := orgpolicy.Decision{Allow: false, Reason: "local policy deny"}
	if orgpolicy.Compose(context.Background(), b, local, "read", "production").Allow {
		t.Error("expected deny (local-deny wins), got allow")
	}
}

func TestCompose_OrgAllowLocalNarrow(t *testing.T) {
	b := &orgpolicy.OrgBundle{
		AllowedEnvelope: orgpolicy.AllowedEnvelope{AllowedEnvs: []string{"production", "staging"}},
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	local := orgpolicy.Decision{Allow: true, Reason: "local allow"}
	if !orgpolicy.Compose(context.Background(), b, local, "read", "staging").Allow {
		t.Error("expected allow (org allows staging, local allows), got deny")
	}
}

func TestCompose_NilBundle_PassThrough(t *testing.T) {
	local := orgpolicy.Decision{Allow: true, Reason: "local"}
	if !orgpolicy.Compose(context.Background(), nil, local, "write", "production").Allow {
		t.Error("nil bundle should pass through local decision")
	}
}
