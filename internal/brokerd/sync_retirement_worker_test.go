//go:build unix

package brokerd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/brokerstore"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/control"
	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/keylatch/keylatch/internal/sync/targets"
	"github.com/stretchr/testify/require"
)

func scheduleTestRotation(t *testing.T) (*syncRig, *partition) {
	t.Helper()
	r := newSyncRig(t)
	p, err := r.h.srv.partition(context.Background(), r.uid)
	require.NoError(t, err)
	_, err = p.store.Put(context.Background(), "app-db/url", []byte("new-value"))
	require.NoError(t, err)
	m := strings.Replace(syncManifest, ", local: [file]", "", 1)
	req := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncRotate, Sync: &brokerapi.SyncRequest{
		Manifest: []byte(m), Name: "DATABASE_URL", KeepOldSeconds: 3600,
	}})
	resp := r.h.send(t, r.uid, req)
	require.True(t, resp.OK, resp.Error)
	require.NotEmpty(t, resp.Sync.Entries)
	for _, entry := range resp.Sync.Entries {
		require.Equal(t, keysync.OutcomeRetirementPending, entry.Outcome)
	}
	require.Zero(t, r.h.rec.count(audit.ActionSyncRotateComplete))
	old, _, err := p.store.GetVersion(context.Background(), "app-db/url", 1)
	require.NoError(t, err)
	require.Equal(t, syncCanary+"-db", string(old))
	clear(old)
	return r, p
}

func TestRetirementWorkerResumesAfterRestart(t *testing.T) {
	r, _ := scheduleTestRotation(t)
	cfg := r.h.srv.cfg
	at := cfg.Now().Add(time.Hour)
	cfg.Now = func() time.Time { return at }
	restarted, err := New(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.Serve(ctx, &pipeListener{ch: make(chan control.Conn)}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("retirement worker did not stop")
		}
	})
	require.Eventually(t, func() bool { return r.h.rec.count(audit.ActionSyncRotateComplete) == 1 }, 5*time.Second, 10*time.Millisecond)
	p, err := restarted.partition(context.Background(), r.uid)
	require.NoError(t, err)
	_, _, err = p.store.GetVersion(context.Background(), "app-db/url", 1)
	require.ErrorIs(t, err, brokerstore.ErrRetired)
}

func TestRetirementWorkerPreservesJobAfterAuditFailure(t *testing.T) {
	r, p := scheduleTestRotation(t)
	ctx := context.Background()
	*r.h.now = r.h.now.Add(time.Hour)
	r.h.rec.fail = errors.New("audit unavailable")
	require.Error(t, r.h.srv.processRetirementsLocked(ctx, p))
	old, _, err := p.store.GetVersion(ctx, "app-db/url", 1)
	require.NoError(t, err)
	clear(old)
	q := &retirementQueue{store: p.store}
	jobs, err := q.due(ctx, *r.h.now)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	r.h.rec.fail = nil
	require.NoError(t, r.h.srv.processRetirementsLocked(ctx, p))
	_, _, err = p.store.GetVersion(ctx, "app-db/url", 1)
	require.ErrorIs(t, err, brokerstore.ErrRetired)
	jobs, err = q.due(ctx, *r.h.now)
	require.NoError(t, err)
	require.Empty(t, jobs)
	require.Equal(t, 1, r.h.rec.count(audit.ActionSyncRotateComplete))
}

func TestRotationWaitsForEnvFileCommit(t *testing.T) {
	r := newSyncRig(t)
	ctx := context.Background()
	p, err := r.h.srv.partition(ctx, r.uid)
	require.NoError(t, err)
	_, err = p.store.Put(ctx, "app-db/url", []byte("new-value"))
	require.NoError(t, err)
	current, old, meta, ref, err := p.store.SnapshotForRetirement(ctx, "app-db/url")
	require.NoError(t, err)
	defer clear(current)
	defer clear(old)
	engine := &keysync.Engine{Manifest: keysync.Manifest{Targets: map[string]keysync.Target{"local": {Type: keysync.TypeEnvFile}}}}
	a := &admin{s: r.h.srv, p: p}
	pending, err := a.finishRotation(ctx, engine, keysync.Var{Name: "DATABASE_URL", To: map[string][]string{"local": {"file"}}}, keysync.SourceSnapshot{
		Path: ref.Path, Version: meta.Version, CurrentID: ref.CurrentID, PreviousID: ref.PreviousID, Current: current, Previous: old,
	}, []string{"local"}, 0, "0123456789abcdef")
	require.NoError(t, err)
	require.True(t, pending)
	jobs, err := (&retirementQueue{store: p.store}).due(ctx, r.h.srv.cfg.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Empty(t, jobs)
	retained, _, err := p.store.GetVersion(ctx, "app-db/url", 1)
	require.NoError(t, err)
	clear(retained)
	require.Zero(t, r.h.rec.count(audit.ActionSyncRotateComplete))
}

func TestRotationRetainsHistoryUntilAllTargetsUpdate(t *testing.T) {
	r := newSyncRig(t)
	ci := newFakeRemote("vercel:prj_2")
	r.h.srv.cfg.Sync.Target = func(name string, _ keysync.Target, _ targets.Token) (keysync.TargetClient, bool) {
		if name == "ci" {
			return ci, true
		}
		return r.web, true
	}
	m := strings.Replace(syncManifest, "local: {type: env-file, path: .env.local}", "ci: {type: vercel, project: prj_2, credential: vercel-deploy}", 1)
	m = strings.Replace(m, "local: [file]", "ci: [production]", 1)
	ctx := context.Background()
	p, err := r.h.srv.partition(ctx, r.uid)
	require.NoError(t, err)
	_, err = p.store.Put(ctx, "app-db/url", []byte("new-value"))
	require.NoError(t, err)
	for _, target := range []string{"web", "ci"} {
		req := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncRotate, Sync: &brokerapi.SyncRequest{
			Manifest: []byte(m), Name: "DATABASE_URL", Target: target,
		}})
		resp := r.h.send(t, r.uid, req)
		require.True(t, resp.OK, resp.Error)
		old, _, readErr := p.store.GetVersion(ctx, "app-db/url", 1)
		clear(old)
		if target == "web" {
			require.NoError(t, readErr)
			require.Equal(t, keysync.OutcomeRetirementPending, resp.Sync.Entries[0].Outcome)
			require.Zero(t, r.h.rec.count(audit.ActionSyncRotateComplete))
		} else {
			require.ErrorIs(t, readErr, brokerstore.ErrRetired)
			require.Equal(t, keysync.OutcomeVerified, resp.Sync.Entries[0].Outcome)
			require.Equal(t, 2, r.h.rec.count(audit.ActionSyncRotateComplete))
		}
	}
}
