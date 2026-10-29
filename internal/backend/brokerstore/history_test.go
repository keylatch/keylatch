package brokerstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/stretchr/testify/require"
)

func TestHistorySurvivesReopenAndKeyRotation(t *testing.T) {
	ctx := context.Background()
	h := newKeys(t)
	dir := t.TempDir()
	s := newStore(t, h, dir, "1000")
	for i := 1; i <= 3; i++ {
		version, err := s.Put(ctx, "app/key", []byte(fmt.Sprintf("secret-version-%d", i)))
		require.NoError(t, err)
		require.Equal(t, i, version)
	}
	s = newStore(t, h, dir, "1000")
	var previous record
	require.NoError(t, readJSON(s.versionFile("app/key", 1), &previous))
	count := 0
	require.NoError(t, h.Rotate(func(old, next keys.KEKFunc, id string) error {
		var err error
		count, err = s.Rewrap(old("1000"), next("1000"), id)
		return err
	}))
	require.Equal(t, 3, count)
	var rewrapped record
	require.NoError(t, readJSON(s.versionFile("app/key", 1), &rewrapped))
	require.Equal(t, previous.CT, rewrapped.CT)
	require.NotEqual(t, previous.KID, rewrapped.KID)
	for i := 1; i <= 3; i++ {
		value, meta, err := s.GetVersion(ctx, "app/key", i)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("secret-version-%d", i), string(value))
		require.Equal(t, i, meta.Version)
		clear(value)
	}
	entries, err := s.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, 3, entries[0].Version)
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		require.NoError(t, err)
		require.False(t, bytes.Contains(data, []byte("secret-version-")))
	}
	require.NoError(t, s.Delete(ctx, "app/key"))
	files, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, files)
}

func TestHistoryRejectsSubstitutionAndCorruptCurrentRecord(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	for _, value := range []string{"one", "two", "three"} {
		_, err := s.Put(ctx, "app/key", []byte(value))
		require.NoError(t, err)
	}
	first, err := os.ReadFile(s.versionFile("app/key", 1))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(s.versionFile("app/key", 2), first, 0o600))
	_, _, err = s.GetVersion(ctx, "app/key", 2)
	require.ErrorIs(t, err, ErrAAD)
	current := readRecord(t, s, "app/key")
	current.CT[0] ^= 1
	writeRecordAt(t, s, "app/key", current)
	_, _, err = s.GetVersion(ctx, "app/key", 1)
	require.ErrorIs(t, err, ErrAAD)
	_, err = s.Put(ctx, "app/key", []byte("replacement"))
	require.ErrorIs(t, err, ErrAAD)
	require.Equal(t, current, readRecord(t, s, "app/key"))
}

func TestHistoryArchiveFailurePreservesCurrentAndDeletionDeniesOrphans(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	_, err := s.Put(ctx, "key", []byte("one"))
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(s.versionFile("key", 1), 0o700))
	_, err = s.Put(ctx, "key", []byte("two"))
	require.Error(t, err)
	value, meta, err := s.Get(ctx, "key")
	require.NoError(t, err)
	require.Equal(t, "one", string(value))
	require.Equal(t, 1, meta.Version)
	require.NoError(t, os.Remove(s.versionFile("key", 1)))
	_, err = s.Put(ctx, "key", []byte("two"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(s.file("key")))
	_, _, err = s.GetVersion(ctx, "key", 1)
	require.ErrorIs(t, err, backend.ErrNotFound)
	require.ErrorIs(t, s.Delete(ctx, "key"), backend.ErrNotFound)
	_, err = os.Stat(s.versionFile("key", 1))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestConcurrentWritesKeepDistinctVersions(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, newKeys(t), t.TempDir(), "1000")
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			if _, err := s.Put(ctx, "key", []byte(fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	values := map[string]bool{}
	for i := 1; i <= 12; i++ {
		value, meta, err := s.GetVersion(ctx, "key", i)
		require.NoError(t, err)
		require.Equal(t, i, meta.Version)
		values[string(value)] = true
	}
	require.Len(t, values, 12)
	for _, version := range []int{-1, 0, 13} {
		_, _, err := s.GetVersion(ctx, "key", version)
		require.Error(t, err)
	}
}
