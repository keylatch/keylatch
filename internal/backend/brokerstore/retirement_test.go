package brokerstore

import (
	"context"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/stretchr/testify/require"
)

func retirementFixture(t *testing.T, s *Store) Retirement {
	t.Helper()
	ctx := context.Background()
	for _, value := range []string{"previous-secret", "current-secret"} {
		_, err := s.Put(ctx, "app/key", []byte(value))
		require.NoError(t, err)
	}
	current, previous, meta, ref, err := s.SnapshotForRetirement(ctx, "app/key")
	require.NoError(t, err)
	require.Equal(t, "current-secret", string(current))
	require.Equal(t, "previous-secret", string(previous))
	require.Equal(t, 2, meta.Version)
	require.Equal(t, 2, ref.CurrentVersion)
	clear(current)
	clear(previous)
	return ref
}

func TestRetirementSurvivesReopenAndRewrap(t *testing.T) {
	ctx := context.Background()
	h := newKeys(t)
	dir := t.TempDir()
	s := newStore(t, h, dir, "1000")
	ref := retirementFixture(t, s)
	rotate := func() {
		t.Helper()
		require.NoError(t, h.Rotate(func(old, next keys.KEKFunc, id string) error {
			_, err := s.Rewrap(old("1000"), next("1000"), id)
			return err
		}))
	}
	rotate()
	require.NoError(t, s.Retire(ctx, ref))
	var tombstone record
	require.NoError(t, readJSON(s.versionFile("app/key", 1), &tombstone))
	require.True(t, tombstone.Retired)
	payload, err := s.decryptRecord(tombstone)
	require.NoError(t, err)
	require.Equal(t, ref.PreviousID, string(payload))
	clear(payload)
	rotate()
	s = newStore(t, h, dir, "1000")
	require.NoError(t, s.Retire(ctx, ref))
	value, _, err := s.GetVersion(ctx, "app/key", 1)
	require.ErrorIs(t, err, ErrRetired)
	require.Nil(t, value)
	current, previous, _, empty, err := s.SnapshotForRetirement(ctx, "app/key")
	require.NoError(t, err)
	require.Equal(t, "current-secret", string(current))
	require.Nil(t, previous)
	require.Empty(t, empty)
	clear(current)
	_, err = s.Put(ctx, "app/key", []byte("newest-secret"))
	require.NoError(t, err)
	value, _, err = s.GetVersion(ctx, "app/key", 2)
	require.NoError(t, err)
	require.Equal(t, "current-secret", string(value))
	clear(value)
}

func TestRetirementRefusesChangedOrRecreatedSource(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed", true: "recreated"}[recreate], func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t, newKeys(t), t.TempDir(), "1000")
			ref := retirementFixture(t, s)
			if recreate {
				require.NoError(t, s.Delete(ctx, "app/key"))
				_ = retirementFixture(t, s)
			} else {
				_, err := s.Put(ctx, "app/key", []byte("later-value"))
				require.NoError(t, err)
			}
			require.ErrorIs(t, s.Retire(ctx, ref), ErrVersionChanged)
			old, _, err := s.GetVersion(ctx, "app/key", 1)
			require.NoError(t, err)
			require.Equal(t, "previous-secret", string(old))
			clear(old)
		})
	}
}

func TestRetirementMarkerIsAuthenticated(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	ref := retirementFixture(t, s)
	var original record
	require.NoError(t, readJSON(s.versionFile("app/key", 1), &original))
	forged := original
	forged.Retired = true
	require.NoError(t, s.writeTo(s.versionFile("app/key", 1), forged))
	_, _, _, err := s.Snapshot(ctx, "app/key")
	require.ErrorIs(t, err, ErrAAD)
	require.ErrorIs(t, s.Retire(ctx, ref), ErrAAD)
	require.NoError(t, s.writeTo(s.versionFile("app/key", 1), original))
	require.NoError(t, s.Retire(ctx, ref))
	var retired record
	require.NoError(t, readJSON(s.versionFile("app/key", 1), &retired))
	retired.Retired = false
	require.NoError(t, s.writeTo(s.versionFile("app/key", 1), retired))
	_, _, err = s.GetVersion(ctx, "app/key", 1)
	require.ErrorIs(t, err, ErrAAD)
}

func TestRetirementRejectsMalformedAndMismatchedReferences(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	ref := retirementFixture(t, s)
	for _, alter := range []func(*Retirement){
		func(r *Retirement) { r.Path = "../invalid" },
		func(r *Retirement) { r.CurrentVersion = 1 },
		func(r *Retirement) { r.CurrentID = "bad" },
		func(r *Retirement) { r.PreviousID = r.CurrentID },
		func(r *Retirement) { r.Path = "missing" },
	} {
		bad := ref
		alter(&bad)
		require.Error(t, s.Retire(ctx, bad))
	}
	require.NoError(t, s.Retire(ctx, ref))
	bad := ref
	bad.PreviousID = ref.CurrentID
	require.ErrorIs(t, s.Retire(ctx, bad), ErrVersionChanged)
	require.NoError(t, s.Delete(ctx, "app/key"))
	require.ErrorIs(t, s.Retire(ctx, ref), backend.ErrNotFound)
	_, err := os.Stat(s.versionFile("app/key", 1))
	require.ErrorIs(t, err, os.ErrNotExist)
}
