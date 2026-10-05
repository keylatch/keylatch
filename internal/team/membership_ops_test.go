package team_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxTeamDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "team")
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	return dir
}

func mxTeam(t *testing.T) *team.Team {
	t.Helper()
	mxTeamDir(t)
	tm, err := team.Init(context.Background(), "Acme", "git@example.invalid:acme/sync.git", "")
	require.NoError(t, err)
	for _, m := range []team.Member{
		{ID: "owner", Role: team.RoleOwner, Status: team.MemberActive},
		{ID: "dev", Role: team.RoleDeveloper, Status: team.MemberActive},
		{ID: "gone", Role: team.RoleViewer, Status: team.MemberSuspended},
	} {
		require.NoError(t, team.AddMember(context.Background(), tm, m))
	}
	return tm
}

func TestTransfer_PromotesAndDemotes(t *testing.T) {
	tm := mxTeam(t)
	require.NoError(t, team.Transfer(context.Background(), tm, "owner", "dev"))

	loaded, err := team.Load(context.Background())
	require.NoError(t, err)
	owner, err := team.FindMember(loaded, "owner")
	require.NoError(t, err)
	dev, err := team.FindMember(loaded, "dev")
	require.NoError(t, err)
	assert.Equal(t, team.RoleAdmin, owner.Role, "previous owner is demoted to admin")
	assert.Equal(t, team.RoleOwner, dev.Role)
}

func TestTransfer_RejectsInactiveOrUnknown(t *testing.T) {
	tm := mxTeam(t)
	err := team.Transfer(context.Background(), tm, "owner", "gone")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active member")
	assert.ErrorIs(t, team.Transfer(context.Background(), tm, "owner", "nobody"), team.ErrMemberNotFound)

	owner, _ := team.FindMember(tm, "owner")
	assert.Equal(t, team.RoleOwner, owner.Role, "failed transfers change nothing")
}

func TestActiveMembersAndFindMember(t *testing.T) {
	tm := mxTeam(t)
	ids := []string{}
	for _, m := range team.ActiveMembers(tm) {
		ids = append(ids, m.ID)
	}
	assert.Equal(t, []string{"owner", "dev"}, ids)
	_, err := team.FindMember(tm, "missing")
	assert.ErrorIs(t, err, team.ErrMemberNotFound)
}

func TestAddMember_DuplicateRejected(t *testing.T) {
	tm := mxTeam(t)
	err := team.AddMember(context.Background(), tm, team.Member{ID: "dev"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Len(t, tm.Members, 3)
}

func TestRemoveMember_RotationCallback(t *testing.T) {
	tm := mxTeam(t)
	orig := team.OnRotateSharedSecrets
	t.Cleanup(func() { team.OnRotateSharedSecrets = orig })

	var rotatedFor string
	team.OnRotateSharedSecrets = func(_ context.Context, _ *team.Team, id string) error {
		rotatedFor = id
		return nil
	}
	require.NoError(t, team.RemoveMember(context.Background(), tm, "dev"))
	assert.Equal(t, "dev", rotatedFor)
	dev, _ := team.FindMember(tm, "dev")
	assert.Equal(t, team.MemberRemoved, dev.Status)

	team.OnRotateSharedSecrets = func(context.Context, *team.Team, string) error { return errors.New("kms down") }
	err := team.RemoveMember(context.Background(), tm, "owner")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation callback failed")
}

func TestSaveLoadRoundTripAndFileMode(t *testing.T) {
	tm := mxTeam(t)
	tm.Name = "Renamed"
	require.NoError(t, team.Save(context.Background(), tm))
	loaded, err := team.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Renamed", loaded.Name)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(os.Getenv("KEYLATCH_TEAM_DIR"), "team.json"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestLoad_Errors(t *testing.T) {
	dir := mxTeamDir(t)
	_, err := team.Load(context.Background())
	assert.ErrorIs(t, err, team.ErrTeamNotConfigured)

	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "team.json"), []byte("{bad"), 0o600))
	_, err = team.Load(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")

	require.NoError(t, os.Remove(filepath.Join(dir, "team.json")))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "team.json"), 0o700))
	_, err = team.Load(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestWriteTeam_Errors(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv("KEYLATCH_TEAM_DIR", filepath.Join(blocker, "team"))
	_, err := team.Init(context.Background(), "x", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")

	dir := filepath.Join(t.TempDir(), "team")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "team.json", "occupied"), 0o700))
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	err = team.Save(context.Background(), &team.Team{ID: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename")
	_, statErr := os.Stat(filepath.Join(dir, "team.json.tmp"))
	assert.True(t, os.IsNotExist(statErr), "temp file is cleaned up")
}

func mxTamper(t *testing.T, raw []byte, mutate func(b map[string]any)) []byte {
	t.Helper()
	dec, err := base64.StdEncoding.DecodeString(string(raw))
	require.NoError(t, err)
	var b map[string]any
	require.NoError(t, json.Unmarshal(dec, &b))
	mutate(b)
	enc, err := json.Marshal(b)
	require.NoError(t, err)
	return []byte(base64.StdEncoding.EncodeToString(enc))
}

func TestJoin_VerifiesBundle(t *testing.T) {
	tm := mxTeam(t)
	invite, err := team.CreateInvite(context.Background(), tm, "hmac-of-email", team.RoleDeveloper)
	require.NoError(t, err)
	key := tm.InvitePubKey
	require.NotEmpty(t, key)

	// Joining happens on another machine: a fresh team directory.
	mxTeamDir(t)

	_, err = team.Join(context.Background(), []byte("!!!not base64"), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode invite bundle")

	_, err = team.Join(context.Background(), []byte(base64.StdEncoding.EncodeToString([]byte("not json"))), key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse invite bundle")

	escalated := mxTamper(t, invite, func(b map[string]any) { b["role"] = "owner" })
	_, err = team.Join(context.Background(), escalated, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature", "a tampered role must be rejected")

	expired := mxTamper(t, invite, func(b map[string]any) {
		b["expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	})
	_, err = team.Join(context.Background(), expired, key)
	require.Error(t, err, "changing expiry breaks the signature or is expired")

	_, err = team.Join(context.Background(), invite, "not-a-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invite public key")

	joined, err := team.Join(context.Background(), invite, key)
	require.NoError(t, err)
	assert.Equal(t, tm.ID, joined.ID)
	assert.Equal(t, "Acme", joined.Name)
	assert.Equal(t, key, joined.InvitePubKey)

	_, err = team.Join(context.Background(), invite, key)
	assert.ErrorIs(t, err, team.ErrAlreadyJoined)
}

func TestJoin_RefusesSecondTeam(t *testing.T) {
	other := &team.Team{ID: "other-team-id", Name: "Other"}
	mxTeamDir(t)
	invite, err := team.CreateInvite(context.Background(), other, "h", team.RoleViewer)
	require.NoError(t, err)

	mxTeam(t)
	_, err = team.Join(context.Background(), invite, other.InvitePubKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already joined a different team")
}

func TestRoleLevel(t *testing.T) {
	assert.Equal(t, 0, team.RoleLevel(team.Role("superuser")))
	assert.ErrorIs(t, team.RequireRole(team.Member{Role: "superuser"}, team.RoleViewer), team.ErrRoleInsufficient, "unknown roles have no privilege")
	assert.NoError(t, team.RequireRole(team.Member{Role: team.RoleOwner}, team.RoleAdmin))
}
