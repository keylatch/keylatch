package team_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
)

func TestInit_Load_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	ctx := context.Background()
	got, err := team.Init(ctx, "my-team", "ssh://git/repo", "cosign-pub-key")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got.Name != "my-team" {
		t.Errorf("Name = %q, want %q", got.Name, "my-team")
	}
	if got.ID == "" {
		t.Error("ID should not be empty")
	}

	loaded, err := team.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ID != got.ID {
		t.Errorf("ID mismatch: got %q, want %q", loaded.ID, got.ID)
	}
	if loaded.Name != got.Name {
		t.Errorf("Name mismatch: got %q, want %q", loaded.Name, got.Name)
	}
}

func TestLoad_ErrTeamNotConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	_, err := team.Load(context.Background())
	if err == nil {
		t.Fatal("expected ErrTeamNotConfigured, got nil")
	}
	if err != team.ErrTeamNotConfigured {
		t.Errorf("error = %v, want ErrTeamNotConfigured", err)
	}
}

func TestJoin_VerifiesSignedBundle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	ctx := context.Background()
	// Init team in one "user's" dir.
	initDir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", initDir)
	orig, err := team.Init(ctx, "shared-team", "ssh://git/repo", "cosign-pub")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	bundle, err := team.CreateInvite(ctx, orig, team.HMACValue(orig.ID, "alice@example.com"), team.RoleDeveloper)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	// Switch to second user's dir.
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	joined, err := team.Join(ctx, bundle)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if joined.ID != orig.ID {
		t.Errorf("joined team ID = %q, want %q", joined.ID, orig.ID)
	}
}

func TestJoin_InvalidSignature(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	// Tamper with the bundle.
	ctx := context.Background()
	origDir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", origDir)
	orig, err := team.Init(ctx, "team", "ssh://git/repo", "cosign-pub")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	bundle, err := team.CreateInvite(ctx, orig, "alice-hmac", team.RoleDeveloper)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	// Corrupt the bundle.
	bundle[len(bundle)/2] ^= 0xFF

	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	_, err = team.Join(ctx, bundle)
	if err == nil {
		t.Fatal("expected error for invalid bundle, got nil")
	}
}

func TestRemoveMember_TriggersRotationCallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	ctx := context.Background()
	orig, err := team.Init(ctx, "team", "ssh://git/repo", "cosign-pub")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	member := team.Member{
		ID:       "member-1",
		HMAC:     team.HMACValue(orig.ID, "alice@example.com"),
		Role:     team.RoleDeveloper,
		JoinedAt: time.Now(),
		Status:   team.MemberActive,
	}
	if err := team.AddMember(ctx, orig, member); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	var rotatedMemberID string
	team.OnRotateSharedSecrets = func(_ context.Context, _ *team.Team, memberID string) error {
		rotatedMemberID = memberID
		return nil
	}
	t.Cleanup(func() { team.OnRotateSharedSecrets = nil })

	if err := team.RemoveMember(ctx, orig, "member-1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if rotatedMemberID != "member-1" {
		t.Errorf("rotation callback got memberID=%q, want %q", rotatedMemberID, "member-1")
	}
}

func TestRequireRole(t *testing.T) {
	owner := team.Member{ID: "owner", Role: team.RoleOwner, Status: team.MemberActive}
	admin := team.Member{ID: "admin", Role: team.RoleAdmin, Status: team.MemberActive}
	dev := team.Member{ID: "dev", Role: team.RoleDeveloper, Status: team.MemberActive}

	// Owner passes all.
	for _, minRole := range []team.Role{team.RoleOwner, team.RoleAdmin, team.RoleDeveloper, team.RoleViewer} {
		if err := team.RequireRole(owner, minRole); err != nil {
			t.Errorf("owner denied role=%v: %v", minRole, err)
		}
	}

	// Developer denied admin operation.
	if err := team.RequireRole(dev, team.RoleAdmin); err == nil {
		t.Error("expected ErrRoleInsufficient for developer requiring admin, got nil")
	}

	// Admin passes admin.
	if err := team.RequireRole(admin, team.RoleAdmin); err != nil {
		t.Errorf("admin denied admin role: %v", err)
	}

	// Admin denied owner.
	if err := team.RequireRole(admin, team.RoleOwner); err == nil {
		t.Error("expected ErrRoleInsufficient for admin requiring owner, got nil")
	}
}

func TestHMACValue_StableAndTeamScoped(t *testing.T) {
	teamA := "team-aaa"
	teamB := "team-bbb"
	value := "alice@example.com"

	h1 := team.HMACValue(teamA, value)
	h2 := team.HMACValue(teamA, value)
	if h1 != h2 {
		t.Errorf("HMACValue not stable: %q != %q", h1, h2)
	}

	hB := team.HMACValue(teamB, value)
	if h1 == hB {
		t.Error("HMACValue should differ for different teamIDs")
	}
}

func TestErrTeamNotConfigured_FileAbsent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", filepath.Join(dir, "nonexistent"))
	_, err := team.Load(context.Background())
	if err != team.ErrTeamNotConfigured {
		t.Errorf("got %v, want ErrTeamNotConfigured", err)
	}
}

func init() {
	// Set the team file to a temp location for tests that don't set KEYLATCH_TEAM_DIR.
	_ = os.MkdirAll(filepath.Join(os.TempDir(), "keylatch-team-test"), 0o700)
}
