package sync

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

type ambiguousWriteTarget struct {
	*memTarget
	cancel         context.CancelFunc
	failed         bool
	cleanupBounded bool
}

func (a *ambiguousWriteTarget) Write(ctx context.Context, name string, value []byte, envs []string, sensitive bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.failed {
		deadline, ok := ctx.Deadline()
		a.cleanupBounded = ok && time.Until(deadline) <= 30*time.Second
		return a.memTarget.Write(ctx, name, value, envs, sensitive)
	}
	if err := a.memTarget.Write(ctx, name, value, envs, sensitive); err != nil {
		return err
	}
	a.failed = true
	if a.cancel != nil {
		a.cancel()
	}
	return errors.New("connection lost after accepting write")
}

func TestSyncRollbackRestoresAmbiguousWritesAfterCancellation(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "disconnected"}[disconnect], func(t *testing.T) {
			r := rotateRig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := &ambiguousWriteTarget{memTarget: r.web}
			if disconnect {
				target.cancel = cancel
			}
			r.e.Targets["web"] = target
			entries, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{})
			if !errors.Is(err, ErrRotateFailed) || !target.cleanupBounded {
				t.Fatalf("rotation must fail and use bounded cleanup: %v", err)
			}
			for _, remote := range []*memTarget{r.web, r.ci} {
				for _, entry := range remote.entries {
					if entry.Name == "DATABASE_URL" && entry.value != canaryValue+"-db" {
						t.Fatal("an attempted target retained the new value")
					}
				}
			}
			if !slices.ContainsFunc(entries, func(e Entry) bool { return e.Target == "web" && e.Outcome == OutcomeRolledBack }) {
				t.Fatal("ambiguous target was omitted from rollback")
			}
			if r.audit.count(ActionRotateComplete) != 0 {
				t.Fatal("failed rotation reported completion")
			}
		})
	}
}

type failingRotationAudit struct {
	*auditLog
	action string
}

func (a failingRotationAudit) Event(ctx context.Context, action string, fields map[string]any) error {
	if action == a.action {
		return errors.New("audit write failed")
	}
	return a.auditLog.Event(ctx, action, fields)
}

func TestSyncRollbackOnAuditFailure(t *testing.T) {
	for _, action := range []string{ActionWrite, ActionRotateVerify, ActionRotateComplete} {
		t.Run(action, func(t *testing.T) {
			r := rotateRig(t)
			r.e.Audit = failingRotationAudit{r.audit, action}
			_, err := r.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{})
			if !errors.Is(err, ErrRotateFailed) {
				t.Fatalf("audit failure did not fail rotation: %v", err)
			}
			if r.web.value("DATABASE_URL", "production") != canaryValue+"-db" || r.ci.value("DATABASE_URL", "repository") != canaryValue+"-db" {
				t.Fatal("audit failure left a target changed")
			}
		})
	}
}

type droppedRollbackTarget struct {
	*memTarget
	accepted bool
}

func (d *droppedRollbackTarget) Write(ctx context.Context, name string, value []byte, envs []string, sensitive bool) error {
	if d.accepted {
		return nil
	}
	d.accepted = true
	if err := d.memTarget.Write(ctx, name, value, envs, sensitive); err != nil {
		return err
	}
	return errors.New("lost response")
}

func TestSyncRollbackVerifiesRestoration(t *testing.T) {
	r := rotateRig(t)
	r.sec.values["api/"] = canaryValue + "-api2"
	r.e.Targets["web"] = &droppedRollbackTarget{memTarget: r.web}
	entries, err := r.e.Rotate(context.Background(), "API_KEY", RotateOptions{})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatal("expected rotation failure")
	}
	if slices.ContainsFunc(entries, func(e Entry) bool { return e.Outcome == OutcomeRolledBack }) {
		t.Fatal("a silently discarded rollback was reported as successful")
	}
	if r.web.value("API_KEY", "production") != canaryValue+"-api2" {
		t.Fatal("test target did not discard restoration")
	}
}

func TestSyncRollbackReportsAuditFailure(t *testing.T) {
	r := rotateRig(t)
	r.e.Audit = failingRotationAudit{r.audit, ActionRotateRollback}
	r.web.failWrite = canaryValue + "-v2"
	entries, err := r.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatal("expected rotation failure")
	}
	if slices.ContainsFunc(entries, func(e Entry) bool { return e.Outcome == OutcomeRolledBack }) {
		t.Fatal("unaudited rollback was reported as successful")
	}
}

func TestSyncRollbackWhenKeepOldWaitIsCancelled(t *testing.T) {
	r := rotateRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.e.Sleep = func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	}
	_, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{KeepOld: time.Minute})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatalf("cancelled completion did not fail rotation: %v", err)
	}
	if r.web.value("DATABASE_URL", "production") != canaryValue+"-db" || r.ci.value("DATABASE_URL", "repository") != canaryValue+"-db" {
		t.Fatal("cancelled completion left targets changed")
	}
}

type noTimestampTarget struct{ *memTarget }

func (n noTimestampTarget) List(ctx context.Context) ([]Remote, error) {
	entries, err := n.memTarget.List(ctx)
	for i := range entries {
		entries[i].UpdatedAt = time.Time{}
	}
	return entries, err
}

func TestSyncRotationRefusesUnverifiableWriteOnlyTarget(t *testing.T) {
	r := rotateRig(t)
	r.ci.hideValue = true
	r.e.Targets["ci"] = noTimestampTarget{r.ci}
	entries, err := r.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{Target: "ci"})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatal("a write-only target without timestamps verified")
	}
	if slices.ContainsFunc(entries, func(e Entry) bool { return e.Outcome == OutcomeVerified || e.Outcome == OutcomeRolledBack }) {
		t.Fatal("unverifiable write or restoration was reported as verified")
	}
}
