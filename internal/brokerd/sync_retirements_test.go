package brokerd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/brokerstore"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/stretchr/testify/require"
)

func newRetirementQueueFixture(t *testing.T) (*retirementQueue, *keys.Hierarchy, string, retirementJob) {
	t.Helper()
	h, err := keys.Open(t.TempDir(), bytes.Repeat([]byte{42}, 32), false)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	dir := t.TempDir()
	st, err := brokerstore.Open(dir, "1000", h)
	require.NoError(t, err)
	ctx := context.Background()
	for _, value := range []string{"old-value", "new-value"} {
		_, err := st.Put(ctx, "app/key", []byte(value))
		require.NoError(t, err)
	}
	current, previous, _, ref, err := st.SnapshotForRetirement(ctx, "app/key")
	require.NoError(t, err)
	clear(current)
	clear(previous)
	at := time.Unix(1_800_000_000, 0).UTC()
	job := retirementJob{Version: 1, Source: ref, Connection: "app", Field: "key", Name: "PRIVATE_QUEUE_NAME", Targets: []string{"web", "ci"}, Presence: "0123456789abcdef", VerifiedAt: at, NotBefore: at.Add(time.Hour)}
	return &retirementQueue{store: st}, h, dir, job
}

func TestRetirementQueueSurvivesRestartAndKeyRotation(t *testing.T) {
	ctx := context.Background()
	q, h, dir, job := newRetirementQueueFixture(t)
	id, err := q.enqueue(ctx, job)
	require.NoError(t, err)
	jobs, err := q.due(ctx, job.NotBefore.Add(-time.Nanosecond))
	require.NoError(t, err)
	require.Empty(t, jobs)
	retry := job
	retry.VerifiedAt = retry.VerifiedAt.Add(time.Minute)
	retry.NotBefore = retry.NotBefore.Add(time.Minute)
	retry.Targets = []string{"ci", "web"}
	retryID, err := q.enqueue(ctx, retry)
	require.NoError(t, err)
	require.Equal(t, id, retryID)
	require.NoError(t, h.Rotate(func(old, next keys.KEKFunc, kid string) error {
		_, err := q.store.Rewrap(old("1000"), next("1000"), kid)
		return err
	}))
	st, err := brokerstore.Open(dir, "1000", h)
	require.NoError(t, err)
	q = &retirementQueue{store: st}
	jobs, err = q.due(ctx, job.NotBefore)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.Equal(t, job.VerifiedAt, jobs[0].VerifiedAt)
	require.Equal(t, job.NotBefore, jobs[0].NotBefore)
	require.Equal(t, job.Source, jobs[0].Source)
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, file := range files {
		b, err := os.ReadFile(filepath.Join(dir, file.Name()))
		require.NoError(t, err)
		for _, canary := range []string{job.Name, job.Presence, "old-value", "new-value"} {
			require.NotContains(t, string(b), canary)
		}
	}
	require.NoError(t, q.complete(ctx, jobs[0]))
	require.NoError(t, q.complete(ctx, jobs[0]))
	_, _, err = q.store.Get(ctx, retirementPrefix+id)
	require.ErrorIs(t, err, backend.ErrNotFound)
	value, _, err := q.store.Get(ctx, "app/key")
	require.NoError(t, err)
	require.Equal(t, "new-value", string(value))
	clear(value)
}

func TestRetirementQueueRejectsInvalidJobs(t *testing.T) {
	ctx := context.Background()
	q, _, _, job := newRetirementQueueFixture(t)
	for _, alter := range []func(*retirementJob){
		func(j *retirementJob) { j.Version = 2 },
		func(j *retirementJob) { j.Source.Path = "../outside" },
		func(j *retirementJob) { j.Source.Path = ".sync/retirements/other" },
		func(j *retirementJob) { j.Source.CurrentVersion = 1 },
		func(j *retirementJob) { j.Source.PreviousID = "invalid" },
		func(j *retirementJob) { j.Presence = "invalid" },
		func(j *retirementJob) { j.Name = "" },
		func(j *retirementJob) { j.Targets = []string{"web", "web"} },
		func(j *retirementJob) { j.Targets = []string{""} },
		func(j *retirementJob) { j.NotBefore = j.VerifiedAt.Add(-time.Second) },
		func(j *retirementJob) { j.NotBefore = j.VerifiedAt.Add(25 * time.Hour) },
	} {
		bad := job
		alter(&bad)
		_, err := q.enqueue(ctx, bad)
		require.Error(t, err)
		require.Error(t, q.complete(ctx, bad))
	}
	entries, err := q.store.List(ctx, retirementPrefix)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestRetirementQueueRejectsAlteredAndMalformedPersistedJobs(t *testing.T) {
	ctx := context.Background()
	q, _, _, job := newRetirementQueueFixture(t)
	id := job.id()
	b, err := json.Marshal(job)
	require.NoError(t, err)
	changed := job
	changed.Source.PreviousID = changed.Source.CurrentID
	changedBytes, err := json.Marshal(changed)
	require.NoError(t, err)
	unknown := strings.TrimSuffix(string(b), "}") + `,"unexpected":true}`
	for _, payload := range [][]byte{[]byte("broken"), []byte(unknown), append(append([]byte{}, b...), []byte(" {}")...), changedBytes} {
		_, err := q.store.Put(ctx, retirementPrefix+id, payload)
		require.NoError(t, err)
		_, err = q.due(ctx, job.NotBefore)
		require.Error(t, err)
		_, err = q.enqueue(ctx, job)
		require.Error(t, err)
		require.Error(t, q.complete(ctx, job))
	}
	_, err = q.read(ctx, "../outside")
	require.Error(t, err)
}
