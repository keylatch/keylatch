package team_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/bundlesig"
)

// issueInvite creates a team in its own directory, issues one invite and
// returns the decoded bundle with the team's invite public key.
func issueInvite(t *testing.T) (team.InviteBundle, string) {
	t.Helper()
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	ctx := context.Background()
	orig, err := team.Init(ctx, "team", "ssh://git/repo", "")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	raw, err := team.CreateInvite(ctx, orig, "alice-hmac", team.RoleDeveloper)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if orig.InvitePubKey == "" {
		t.Fatal("CreateInvite did not record the team's invite public key")
	}
	saved, err := team.Load(ctx)
	if err != nil || saved.InvitePubKey != orig.InvitePubKey {
		t.Fatalf("invite public key not persisted: %v", err)
	}
	return decodeInvite(t, raw), orig.InvitePubKey
}

func decodeInvite(t *testing.T, raw []byte) team.InviteBundle {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	var b team.InviteBundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeInvite(t *testing.T, b team.InviteBundle) []byte {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// legacyInviteSignature reproduces the unkeyed SHA-256 digest that releases
// up to 0.9.8 wrote as an invite "signature".
func legacyInviteSignature(b team.InviteBundle) string {
	h := sha256.New()
	for _, f := range []string{
		b.TeamID, b.TeamName, b.SyncRepoURL, b.MemberHMAC, string(b.Role),
		b.IssuedAt.UTC().Format(time.RFC3339Nano), b.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"keylatch/team/invite/v1/" + b.TeamID,
	} {
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func joinAs(t *testing.T, b team.InviteBundle, key string) error {
	t.Helper()
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	_, err := team.Join(context.Background(), encodeInvite(t, b), key)
	return err
}

func TestJoinAcceptsInviteSignedByTeamKey(t *testing.T) {
	b, key := issueInvite(t)
	if !strings.HasPrefix(b.Signature, "ed25519:") {
		t.Fatalf("signature %q is not an Ed25519 signature", b.Signature)
	}
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	joined, err := team.Join(context.Background(), encodeInvite(t, b), key)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if joined.ID != b.TeamID || joined.InvitePubKey != key {
		t.Fatalf("joined team = %+v, want ID %q pinned to the invite key", joined, b.TeamID)
	}
}

func TestJoinRejectsTamperedInvite(t *testing.T) {
	b, key := issueInvite(t)
	b.Role = team.RoleOwner
	if err := joinAs(t, b, key); !errors.Is(err, bundlesig.ErrInvalidSignature) {
		t.Fatalf("Join with escalated role: got %v, want ErrInvalidSignature", err)
	}
}

func TestJoinRejectsRecomputedLegacyInvite(t *testing.T) {
	b, key := issueInvite(t)
	b.Role = team.RoleOwner
	b.Signature = legacyInviteSignature(b)
	err := joinAs(t, b, key)
	if !errors.Is(err, bundlesig.ErrLegacySignature) {
		t.Fatalf("Join with a recomputed legacy digest: got %v, want ErrLegacySignature", err)
	}
	if !strings.Contains(err.Error(), "keylatch team invite") {
		t.Errorf("error %q does not say how to re-issue the invite", err)
	}
}

func TestJoinRejectsUnsignedInvite(t *testing.T) {
	b, key := issueInvite(t)
	b.Signature = ""
	if err := joinAs(t, b, key); !errors.Is(err, bundlesig.ErrUnsigned) {
		t.Fatalf("Join unsigned: got %v, want ErrUnsigned", err)
	}
}

func TestJoinRejectsInviteFromAnotherKey(t *testing.T) {
	b, _ := issueInvite(t)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := joinAs(t, b, bundlesig.EncodePublicKey(other)); !errors.Is(err, bundlesig.ErrInvalidSignature) {
		t.Fatalf("Join with the wrong key: got %v, want ErrInvalidSignature", err)
	}
}

func TestJoinRequiresTeamKey(t *testing.T) {
	b, _ := issueInvite(t)
	if err := joinAs(t, b, ""); !errors.Is(err, bundlesig.ErrNoTrustedKey) {
		t.Fatalf("Join without a key: got %v, want ErrNoTrustedKey", err)
	}
}

func TestJoinRejectsKeyDifferentFromJoinedTeam(t *testing.T) {
	b, key := issueInvite(t)
	ctx := context.Background()

	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	impostor := &team.Team{ID: b.TeamID, Name: b.TeamName}
	if err := team.Save(ctx, impostor); err != nil {
		t.Fatal(err)
	}
	forged, err := team.CreateInvite(ctx, impostor, "mallory-hmac", team.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}

	joinDir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", joinDir)
	if _, err := team.Join(ctx, encodeInvite(t, b), key); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if _, err := os.Stat(filepath.Join(joinDir, "invite-signing.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("joining created an invite signing key: %v", err)
	}
	if _, err := team.Join(ctx, forged, impostor.InvitePubKey); err == nil ||
		!strings.Contains(err.Error(), "invite key differs") {
		t.Fatalf("Join with a second team key: got %v", err)
	}
}

func TestCreateInviteRefusesWithoutTeamSigningKey(t *testing.T) {
	_, key := issueInvite(t)
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	member := &team.Team{ID: "team-id", Name: "team", InvitePubKey: key}
	if _, err := team.CreateInvite(context.Background(), member, "bob-hmac", team.RoleDeveloper); err == nil ||
		!strings.Contains(err.Error(), "does not hold the team's invite signing key") {
		t.Fatalf("CreateInvite without the signing key: got %v", err)
	}
}

func TestInviteSigningKeyIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	tm, err := team.Init(ctx, "team", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := team.CreateInvite(ctx, tm, "alice-hmac", team.RoleViewer); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "invite-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("invite signing key mode = %v, want 0600", info.Mode().Perm())
	}
}
