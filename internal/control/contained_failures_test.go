//go:build !windows

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/redactor"
)

// lostChild reports that the sandbox could not be waited on after it ended.
type lostChild struct{ contained.Child }

func (c lostChild) Wait() (int, error) {
	_, _ = c.Child.Wait()
	return 0, errors.New("lost the sandbox")
}

type lostLauncher struct{ inner contained.Launcher }

func (l lostLauncher) Start(spec contained.Spec) (contained.Child, error) {
	child, err := l.inner.Start(spec)
	if err != nil {
		return nil, err
	}
	return lostChild{child}, nil
}

func TestContainedRunIsRefusedWhenTheAuditLogCannotRecordIt(t *testing.T) {
	for name, mutate := range map[string]func(*Request){
		"a run that would start":       func(*Request) {},
		"a refusal that must be saved": func(r *Request) { r.Run.Connection = "nope-nope" },
	} {
		t.Run(name, func(t *testing.T) {
			w := newContainedWorld(t)
			w.srv.cfg.Audit = failingAudit{}
			req := w.request()
			mutate(&req)
			res := w.runRaw(req, nil)
			assert.False(t, res.final.OK)
			assert.Equal(t, CodeRefused, res.final.Code)
			assert.Equal(t, exitcode.SecurityBlock, res.final.ExitCode)
			assert.Contains(t, res.final.Error, "cannot record this decision")
			assert.Zero(t, w.launcher.started(), "Keylatch does not act without an audit trail")
		})
	}
}

func TestContainedRunReportsSandboxSetupFailures(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	for name, tc := range map[string]struct {
		mutate func(*ContainedConfig)
		reason string
	}{
		"no state directory":       {func(c *ContainedConfig) { c.StateDir = "" }, "no state directory is configured"},
		"unusable state directory": {func(c *ContainedConfig) { c.StateDir = filepath.Join(notADir, "runs") }, "could not prepare the sandbox"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newContainedWorld(t)
			tc.mutate(w.srv.cfg.Contained)
			res := w.runRaw(w.request(), nil)
			assert.False(t, res.final.OK)
			assert.Equal(t, CodeUnavailable, res.final.Code)
			assert.Equal(t, exitcode.OperationFailed, res.final.ExitCode)
			assert.Contains(t, res.final.Error, tc.reason)
			assert.Zero(t, w.launcher.started())
		})
	}
}

func TestContainedRunReportsAnEgressSocketItCannotOpen(t *testing.T) {
	w := newContainedWorld(t)
	w.srv.cfg.Contained.Listen = func(string) (net.Listener, error) { return nil, errors.New("address in use") }
	res := w.runRaw(w.request(), nil)
	assert.False(t, res.final.OK)
	assert.Equal(t, CodeUnavailable, res.final.Code)
	assert.Contains(t, res.final.Error, "could not open the sandbox egress socket: address in use")
	assert.Zero(t, w.launcher.started())
	exited := w.events(audit.ActionRunExited)
	require.Len(t, exited, 1)
	assert.Equal(t, "sandbox egress socket", exited[0].Extra["reason"])
	assert.Equal(t, audit.OutcomeError, exited[0].Outcome)
}

func TestContainedRunReportsASandboxItCannotWaitOn(t *testing.T) {
	w := newContainedWorld(t)
	w.srv.cfg.Contained.Launcher = lostLauncher{w.launcher}
	res := w.runRaw(w.request(), nil)
	assert.False(t, res.final.OK)
	assert.Equal(t, CodeUnavailable, res.final.Code)
	assert.Equal(t, exitcode.OperationFailed, res.final.ExitCode)
	assert.Contains(t, res.final.Error, "sandbox: lost the sandbox")
}

func TestPlanContainedCapsTheRunAndMergesHosts(t *testing.T) {
	w := newContainedWorld(t)
	w.decide = func(enforce.Request) enforce.Decision {
		return enforce.Decision{Allow: true, Approval: "auto", MaxTTL: 90 * time.Second, EgressAllow: []string{"z.example", "a.example", "z.example"}}
	}
	plan, refused := w.srv.planContained(context.Background(), KindHuman, w.request().Run)
	require.Nil(t, refused)
	assert.Equal(t, 90*time.Second, plan.maxRun, "the policy's lifetime caps the run")
	assert.Equal(t, []string{"a.example", "api.stripe.com", "files.stripe.com", "z.example"}, plan.hosts, "bound hosts and extra egress are merged, sorted and unique")
	assert.Equal(t, plan.project, plan.spec.Project)
	assert.Equal(t, []string{"make", "test"}, plan.spec.Argv)
	assert.NotZero(t, plan.spec.Limits.PIDs)
}

func TestReadOnlyPathsResolveDedupeAndRefuseCredentials(t *testing.T) {
	w := newContainedWorld(t)
	resolve := func(p string) string {
		r, err := filepath.EvalSymlinks(p)
		require.NoError(t, err)
		return r
	}
	cache, extra := t.TempDir(), t.TempDir()
	cc := &ContainedConfig{ReadOnly: []string{cache, cache, filepath.Join(cache, "missing")}}

	got, err := w.srv.readOnlyPaths(cc, []string{extra}, nil)
	require.NoError(t, err)
	want := []string{resolve(cache), resolve(extra)}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	assert.Equal(t, want, got, "a missing path is skipped; the rest are resolved, sorted and unique")

	secret := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(secret, "keys"), 0o700))
	_, err = w.srv.readOnlyPaths(cc, []string{filepath.Join(secret, "keys")}, []string{secret})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holds credentials")
}

func TestContainedAuditEventsCarryNoValues(t *testing.T) {
	w := newContainedWorld(t)
	ctx := context.Background()
	d := decision{runID: "run-9", connection: "stripe", res: callerkind.Result{Kind: KindAgent}}

	w.srv.emitEgressDenied(ctx, "stripe", "evil.example", "not allowed")
	w.srv.emitCanaryTripped(ctx, d, "evil.example", "request line")
	w.srv.emitLeakSuspected(ctx, d, 2)
	w.srv.recordContainedExit(ctx, d, time.Now(), 4, 100, 3, "leak_suspected")
	w.srv.recordContainedExit(ctx, d, time.Now(), 0, 1, 0, "")

	denied := w.events(audit.ActionEgressDenied)
	require.Len(t, denied, 1)
	assert.Equal(t, audit.OutcomeDenied, denied[0].Outcome)
	assert.Equal(t, map[string]any{"provider": "stripe", "host": "evil.example", "reason": "not allowed"}, denied[0].Extra)

	tripped := w.events(audit.ActionCanaryTripped)
	require.Len(t, tripped, 1)
	assert.Equal(t, map[string]any{"run_id": "run-9", "connection": "stripe", "caller_kind": string(KindAgent), "host": "evil.example", "where": "request line"}, tripped[0].Extra)

	leaks := w.events(audit.ActionContainedLeakSuspected)
	require.Len(t, leaks, 1)
	assert.Equal(t, 2, leaks[0].Extra["files"])

	exits := w.events(audit.ActionRunExited)
	require.Len(t, exits, 2)
	assert.Equal(t, audit.OutcomeError, exits[0].Outcome)
	assert.Equal(t, "leak_suspected", exits[0].Extra["reason"])
	assert.EqualValues(t, 3, exits[0].Extra["redactions"])
	assert.Equal(t, audit.OutcomeOK, exits[1].Outcome)
	assert.NotContains(t, exits[1].Extra, "reason")

	w.srv.cfg.Audit = nil
	assert.NotPanics(t, func() {
		w.srv.emitEgressDenied(ctx, "stripe", "h", "r")
		w.srv.emitCanaryTripped(ctx, d, "h", "w")
		w.srv.emitLeakSuspected(ctx, d, 1)
		w.srv.recordContainedExit(ctx, d, time.Now(), 0, 0, 0, "")
		w.srv.recordExit(ctx, "op", "", "run", 0, time.Now(), 0, "")
	})
}

func TestFindingPathsNamesAtMostFiveFilesRelativeToTheProject(t *testing.T) {
	root := "/work/project"
	var fs []redactor.Finding
	for i := range 7 {
		fs = append(fs, redactor.Finding{Path: filepath.Join(root, fmt.Sprintf("f%d.txt", i))})
	}
	assert.Equal(t, "f0.txt, f1.txt, f2.txt, f3.txt, f4.txt, and 2 more", findingPaths(fs, root))
	assert.Equal(t, "/elsewhere/x", findingPaths([]redactor.Finding{{Path: "/elsewhere/x"}}, "relative-root"), "an unrelatable path is shown as it is")
}

func TestNewRunDirNeedsAStateDirectory(t *testing.T) {
	w := newContainedWorld(t)
	dir, err := w.srv.newRunDir()
	require.NoError(t, err)
	assert.Equal(t, w.srv.cfg.Contained.StateDir, filepath.Dir(dir))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	w.srv.cfg.Contained.StateDir = ""
	_, err = w.srv.newRunDir()
	assert.ErrorContains(t, err, "no state directory")
}

func TestAuditRefusalDropsWhatWasGranted(t *testing.T) {
	resp := auditRefusal(Response{OK: true, Kind: KindAgent, Session: &Session{RunID: "r"}, Credential: &Credential{Password: "placeholder"}}, errors.New("disk full"))
	assert.False(t, resp.OK)
	assert.Nil(t, resp.Session)
	assert.Nil(t, resp.Credential)
	assert.Equal(t, CodeRefused, resp.Code)
	assert.Equal(t, exitcode.SecurityBlock, resp.ExitCode)
	assert.Equal(t, KindAgent, resp.Kind)
	assert.Contains(t, resp.Error, "disk full")
}

func TestRunTableExpiresRunsWhoseClientNeverReportedAnExit(t *testing.T) {
	var table runTable
	revoked := 0
	stale := &runState{id: "stale", started: time.Now().Add(-3 * sessionTTL), revoke: func() { revoked++ }}
	assert.Empty(t, table.add(stale))
	expired := table.add(&runState{id: "fresh", started: time.Now()})
	require.Len(t, expired, 1)
	assert.Equal(t, "stale", expired[0].id)
	expired[0].end()
	assert.Equal(t, 1, revoked)
	assert.Nil(t, table.get("stale"))
	assert.NotNil(t, table.get("fresh"))

	var none *runState
	assert.NotPanics(t, func() { none.relayed(10) })
	table.get("fresh").relayed(-1)
	table.get("fresh").relayed(7)
	assert.EqualValues(t, 7, table.get("fresh").bytes.Load())
}

func TestRunExitedRevokesTheRunAndAuditsItsStatus(t *testing.T) {
	w := newContainedWorld(t)
	ctx := context.Background()

	missing := w.srv.runExited(ctx, Request{RunID: "nope"})
	assert.False(t, missing.OK)
	assert.Equal(t, CodeNotFound, missing.Code)
	assert.Equal(t, exitcode.Missing, missing.ExitCode)

	revoked := false
	w.srv.runs.add(&runState{id: "run-7", started: time.Now(), revoke: func() { revoked = true }})
	resp := w.srv.runExited(ctx, Request{RunID: "run-7", Exit: 2})
	assert.True(t, resp.OK)
	assert.True(t, revoked, "the run's gateway token ends with the run")
	exits := w.events(audit.ActionRunExited)
	require.Len(t, exits, 1)
	assert.Equal(t, 2, exits[0].Extra["exit"])
	assert.Equal(t, "run-7", exits[0].Extra["run_id"])
	assert.Equal(t, audit.OutcomeError, exits[0].Outcome)
	assert.Nil(t, w.srv.runs.get("run-7"), "a run is reported once")
}
