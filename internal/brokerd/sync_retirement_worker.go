package brokerd

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/brokerstore"
	"github.com/keylatch/keylatch/internal/callerkind"
	keysync "github.com/keylatch/keylatch/internal/sync"
)

func (a *admin) finishRotation(ctx context.Context, engine *keysync.Engine, v keysync.Var, snapshot keysync.SourceSnapshot, selected []string, keep time.Duration, presence string) (bool, error) {
	job := retirementJob{
		Version: 1, Connection: v.From.Connection, Field: v.From.Field, Name: v.Name,
		Presence: presence, VerifiedAt: a.s.cfg.Now().UTC(),
		Source: brokerstore.Retirement{Path: snapshot.Path, CurrentVersion: snapshot.Version, CurrentID: snapshot.CurrentID, PreviousID: snapshot.PreviousID},
	}
	if snapshot.Previous == nil {
		job.Targets = selected
		return false, a.s.retirementEvent(ctx, a.p, job, audit.ActionSyncRotateComplete)
	}
	for target, envs := range v.To {
		// The caller renames env files after the response, so their final commit is not yet proven.
		if engine.Manifest.Targets[target].Type == keysync.TypeEnvFile {
			return true, nil
		}
		client := engine.Targets[target]
		for _, env := range envs {
			written, ok := engine.State.Written(client.ID(), env, v.Name)
			if !ok || written.MAC != engine.State.MAC(client.ID(), env, v.Name, snapshot.Current) {
				return true, nil
			}
		}
		job.Targets = append(job.Targets, target)
	}
	sort.Strings(job.Targets)
	job.NotBefore = job.VerifiedAt.Add(keep)
	q := &retirementQueue{store: a.p.store}
	id, err := q.enqueue(ctx, job)
	if err != nil {
		return true, err
	}
	if err = a.s.retirementEvent(ctx, a.p, job, audit.ActionSyncRotateQueued); err != nil {
		return true, err
	}
	select {
	case a.s.retirementWake <- struct{}{}:
	default:
	}
	if err = a.s.processRetirementsLocked(ctx, a.p); err != nil {
		return true, err
	}
	_, err = q.read(ctx, id)
	if errors.Is(err, backend.ErrNotFound) {
		return false, nil
	}
	return true, err
}

func (s *Server) retirementEvent(ctx context.Context, p *partition, job retirementJob, action audit.Action) error {
	for _, target := range job.Targets {
		if err := s.cfg.Audit.Emit(ctx, audit.Event{Action: action, Outcome: audit.OutcomeOK, Extra: map[string]any{
			"connection": job.Connection, "target": target, "environment": "", "name": job.Name,
			"caller_kind": string(callerkind.Human), "presence": job.Presence, "uid": p.uid,
			"retirement_scope": "backend",
		}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) processRetirementsLocked(ctx context.Context, p *partition) error {
	q := &retirementQueue{store: p.store}
	jobs, err := q.due(ctx, s.cfg.Now())
	if err != nil {
		return err
	}
	var failures []error
	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.retireJob(attempt, p, job)
		cancel()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := q.complete(ctx, job); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Server) retireJob(ctx context.Context, p *partition, job retirementJob) error {
	if err := p.policy.Gate(ctx, callerkind.Result{Kind: callerkind.Human}); err != nil {
		return err
	}
	if err := s.retirementEvent(ctx, p, job, audit.ActionSyncRotateRetire); err != nil {
		return err
	}
	if err := p.store.Retire(ctx, job.Source); err != nil {
		return err
	}
	return s.retirementEvent(ctx, p, job, audit.ActionSyncRotateComplete)
}

func (s *Server) runRetirements(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		uids, err := s.partitions()
		if err != nil {
			slog.Warn("cannot enumerate pending retirements", "error", err)
		}
		for _, uid := range uids {
			if ctx.Err() != nil {
				return
			}
			if !s.cfg.Allow(uid) {
				continue
			}
			p, err := s.partition(ctx, uid)
			if err == nil {
				p.syncMu.Lock()
				err = s.processRetirementsLocked(ctx, p)
				p.syncMu.Unlock()
			}
			if err != nil && ctx.Err() == nil {
				slog.Warn("secret retirement remains pending", "uid", uid, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.retirementWake:
		}
	}
}
