package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Audit actions the engine reports. None carries a value or a hash of one.
const (
	ActionWrite          = "sync.write"
	ActionDelete         = "sync.delete"
	ActionRotateVerify   = "sync.rotate.verify"
	ActionRotateRollback = "sync.rotate.rollback"
	ActionRotateComplete = "sync.rotate.complete"
)

// Entry outcomes.
const (
	OutcomeWritten    = "written"
	OutcomeUnchanged  = "unchanged"
	OutcomeDeleted    = "deleted"
	OutcomeVerified   = "verified"
	OutcomeRolledBack = "rolled-back"
	OutcomeFailed     = "failed"
)

// TargetClient is one target as the engine drives it.
type TargetClient interface {
	// ID is the identity the record of writes is keyed by.
	ID() string
	List(ctx context.Context) ([]Remote, error)
	Write(ctx context.Context, name string, value []byte, envs []string, sensitive bool) error
	Delete(ctx context.Context, r Remote) error
	// Readback returns an entry's value when the target hands values back.
	Readback(ctx context.Context, r Remote) (value []byte, ok bool, err error)
}

// Flusher is a target that buffers its writes.
type Flusher interface {
	Flush(ctx context.Context) error
}

// Secrets reads the sources. Only the daemon holds one.
type Secrets interface {
	Value(ctx context.Context, connection, field string) ([]byte, error)
	// Snapshot binds current and previous backend versions to one source read.
	Snapshot(ctx context.Context, connection, field string) (SourceSnapshot, error)
}

// SourceSnapshot contains daemon-only values and their source version identities.
// Previous is nil when the backend cannot supply an earlier version.
type SourceSnapshot struct {
	Path            string
	Version         int
	PreviousVersion int
	Current         []byte
	Previous        []byte
}

// Recorder is the daemon's record of its own writes.
type Recorder interface {
	State
	// MAC is the keyed hash of a value written to one entry.
	MAC(targetID, env, name string, value []byte) string
	Record(targetID, env, name, mac string, remoteAt time.Time) error
	Forget(targetID, env, name string) error
}

// Auditor receives one event per write, delete and rotation step.
type Auditor interface {
	Event(ctx context.Context, action string, f map[string]any) error
}

// Entry is the outcome for one variable at one target and environment.
type Entry struct {
	Target      string `json:"target"`
	Environment string `json:"environment"`
	Name        string `json:"name"`
	Outcome     string `json:"outcome"`
	Error       string `json:"error,omitempty"`
}

// Engine runs a manifest against its targets.
type Engine struct {
	Manifest Manifest
	Targets  map[string]TargetClient
	Secrets  Secrets
	State    Recorder
	Audit    Auditor
	Now      func() time.Time
	// Probe makes the verification request of a rotation with value.
	Probe func(ctx context.Context, url string, value []byte) error
	// Sleep waits d or until ctx ends; nil uses a timer.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) ids() map[string]string {
	out := map[string]string{}
	for n, t := range e.Targets {
		out[n] = t.ID()
	}
	return out
}

func (e *Engine) list(ctx context.Context) (map[string][]Remote, error) {
	out := map[string][]Remote{}
	for _, name := range e.Manifest.TargetNames() {
		c, ok := e.Targets[name]
		if !ok {
			return nil, fmt.Errorf("sync: target %q has no client", name)
		}
		rs, err := c.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("sync: list %s: %w", name, err)
		}
		out[name] = rs
	}
	return out, nil
}

func (e *Engine) varByName(name string) (Var, bool) {
	for _, v := range e.Manifest.Vars {
		if v.Name == name {
			return v, true
		}
	}
	return Var{}, false
}

// Diff compares the manifest with the targets. With readValues it also
// compares values, through keyed hashes the engine computes itself; without
// it no source is touched.
func (e *Engine) Diff(ctx context.Context, readValues bool) ([]Change, error) {
	remote, err := e.list(ctx)
	if err != nil {
		return nil, err
	}
	return e.compare(ctx, remote, readValues)
}

func (e *Engine) compare(ctx context.Context, remote map[string][]Remote, readValues bool) ([]Change, error) {
	var mac ValueMAC
	if readValues {
		mac = func(v Var, id, env string) (string, error) {
			val, err := e.Secrets.Value(ctx, v.From.Connection, v.From.Field)
			if err != nil {
				return "", fmt.Errorf("sync: read the source of %s: %w", v.Name, err)
			}
			defer clear(val)
			return e.State.MAC(id, env, v.Name, val), nil
		}
	}
	return Compare(e.Manifest, remote, e.ids(), e.State, mac)
}

func (e *Engine) audit(ctx context.Context, action string, f map[string]any) error {
	if e.Audit == nil {
		return nil
	}
	return e.Audit.Event(ctx, action, f)
}

type workKey struct{ target, name string }

// Apply writes every add and update, and with prune deletes every extra. It
// writes an entry only when the comparison says it differs, so a second run
// writes nothing.
func (e *Engine) Apply(ctx context.Context, prune bool) ([]Entry, error) {
	remote, err := e.list(ctx)
	if err != nil {
		return nil, err
	}
	changes, err := e.compare(ctx, remote, true)
	if err != nil {
		return nil, err
	}
	need := map[workKey]bool{}
	for _, c := range changes {
		if c.Kind == KindAdd || c.Kind == KindUpdate {
			need[workKey{c.Target, c.Name}] = true
		}
	}
	var out []Entry
	var pending []pendingWrite
	written := map[string]bool{}
	fail := func(en Entry, err error) { en.Outcome, en.Error = OutcomeFailed, err.Error(); out = append(out, en) }
	for _, tn := range e.Manifest.TargetNames() {
		c := e.Targets[tn]
		for _, v := range e.Manifest.Vars {
			envs, ok := v.To[tn]
			if !ok {
				continue
			}
			if !need[workKey{tn, v.Name}] {
				for _, env := range envs {
					out = append(out, Entry{tn, env, v.Name, OutcomeUnchanged, ""})
				}
				continue
			}
			val, err := e.Secrets.Value(ctx, v.From.Connection, v.From.Field)
			if err != nil {
				for _, env := range envs {
					fail(Entry{Target: tn, Environment: env, Name: v.Name}, fmt.Errorf("read the source: %w", err))
				}
				continue
			}
			err = c.Write(ctx, v.Name, val, envs, v.IsSensitive())
			if err == nil {
				err = e.reshape(ctx, c, v, envs, remote[tn])
			}
			for _, env := range envs {
				en := Entry{Target: tn, Environment: env, Name: v.Name}
				if err != nil {
					fail(en, err)
					continue
				}
				if aerr := e.audit(ctx, ActionWrite, map[string]any{"connection": v.From.Connection, "target": tn, "environment": env, "name": v.Name, "outcome": "ok"}); aerr != nil {
					clear(val)
					return out, aerr
				}
				en.Outcome = OutcomeWritten
				out = append(out, en)
				written[tn] = true
				pending = append(pending, pendingWrite{tn, env, v.Name, e.State.MAC(c.ID(), env, v.Name, val)})
			}
			clear(val)
		}
		if prune {
			pruned, err := e.prune(ctx, tn, c, changes, remote[tn])
			out = append(out, pruned...)
			if err != nil {
				return out, err
			}
			written[tn] = written[tn] || len(pruned) > 0
		}
		if f, ok := c.(Flusher); ok && written[tn] {
			if err := f.Flush(ctx); err != nil {
				return out, fmt.Errorf("sync: finish %s: %w", tn, err)
			}
		}
	}
	return out, e.recordWrites(ctx, pending)
}

type pendingWrite struct{ target, env, name, mac string }

// reshape removes the entries a write replaced. Vercel keeps one entry per
// distinct set of environments, so a variable that moves to other environments
// or another type leaves its old entry behind until the new one exists.
func (e *Engine) reshape(ctx context.Context, c TargetClient, v Var, envs []string, before []Remote) error {
	rs, err := c.List(ctx)
	if err != nil {
		return err
	}
	want := "encrypted"
	if v.IsSensitive() {
		want = "sensitive"
	}
	for _, r := range before {
		if r.Name != v.Name || r.Unmanaged || r.ID == "" || !overlaps(r.Environments, envs) {
			continue
		}
		if sameSet(r.Environments, envs) && (r.Type == "" || r.Type == want) {
			continue
		}
		if !stillListed(rs, r.ID) {
			continue
		}
		if err := c.Delete(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func stillListed(rs []Remote, id string) bool {
	return slices.ContainsFunc(rs, func(r Remote) bool { return r.ID == id })
}

func overlaps(a, b []string) bool {
	return slices.ContainsFunc(a, func(x string) bool { return slices.Contains(b, x) })
}

func (e *Engine) prune(ctx context.Context, tn string, c TargetClient, changes []Change, remote []Remote) ([]Entry, error) {
	extra := map[string]map[string]bool{}
	for _, ch := range changes {
		if ch.Target == tn && ch.Kind == KindExtra {
			if extra[ch.Name] == nil {
				extra[ch.Name] = map[string]bool{}
			}
			extra[ch.Name][ch.Environment] = true
		}
	}
	var out []Entry
	for _, r := range remote {
		if r.Unmanaged || extra[r.Name] == nil {
			continue
		}
		envs := slices.Clone(r.Environments)
		sort.Strings(envs)
		if err := c.Delete(ctx, r); err != nil {
			for _, env := range envs {
				out = append(out, Entry{tn, env, r.Name, OutcomeFailed, err.Error()})
			}
			continue
		}
		for _, env := range envs {
			if err := e.audit(ctx, ActionDelete, map[string]any{"target": tn, "environment": env, "name": r.Name, "outcome": "ok"}); err != nil {
				return out, err
			}
			out = append(out, Entry{tn, env, r.Name, OutcomeDeleted, ""})
			_ = e.State.Forget(c.ID(), env, r.Name)
		}
	}
	return out, nil
}

// recordWrites reads each written target back once and notes the update time
// it reports, so a later change by someone else shows as newer.
func (e *Engine) recordWrites(ctx context.Context, pending []pendingWrite) error {
	byTarget := map[string][]pendingWrite{}
	for _, p := range pending {
		byTarget[p.target] = append(byTarget[p.target], p)
	}
	for tn, ps := range byTarget {
		c := e.Targets[tn]
		rs, err := c.List(ctx)
		if err != nil {
			return fmt.Errorf("sync: read %s back: %w", tn, err)
		}
		for _, p := range ps {
			if err := e.State.Record(c.ID(), p.env, p.name, p.mac, e.updatedAt(rs, p.name, p.env)); err != nil {
				return err
			}
		}
	}
	return nil
}

// updatedAt is the update time the target reports for an entry, or now for a
// target that reports none.
func (e *Engine) updatedAt(rs []Remote, name, env string) time.Time {
	at := e.now()
	for _, r := range rs {
		if r.Name == name && slices.Contains(r.Environments, env) && !r.UpdatedAt.IsZero() {
			at = r.UpdatedAt
		}
	}
	return at
}

// RotateOptions tunes Rotate.
type RotateOptions struct {
	// Target limits the rotation to one target; empty means every target of the variable.
	Target string
	// KeepOld delays completion after every target verified.
	KeepOld time.Duration
	// NoRollback allows a rotation when the backend has no previous version.
	NoRollback bool
}

// ErrRotateFailed wraps the reason a rotation was rolled back.
var ErrRotateFailed = errors.New("sync: the rotation failed")

// Rotate writes the source's current value to every target of a variable,
// verifies each, and records completion. If any target fails
// verification the earlier value is written back and the rotation stops.
func (e *Engine) Rotate(ctx context.Context, name string, opt RotateOptions) ([]Entry, error) {
	v, ok := e.varByName(name)
	if !ok {
		return nil, fmt.Errorf("sync: %q is not a variable in the manifest", name)
	}
	var tns []string
	for _, tn := range e.Manifest.TargetNames() {
		if _, ok := v.To[tn]; ok && (opt.Target == "" || opt.Target == tn) {
			tns = append(tns, tn)
		}
	}
	if len(tns) == 0 {
		return nil, fmt.Errorf("sync: %s has no target %q", name, opt.Target)
	}
	snapshot, err := e.Secrets.Snapshot(ctx, v.From.Connection, v.From.Field)
	if err != nil {
		return nil, fmt.Errorf("sync: read the source of %s: %w", name, err)
	}
	prev, next := snapshot.Previous, snapshot.Current
	defer clear(prev)
	defer clear(next)
	if prev != nil && bytes.Equal(prev, next) {
		return nil, fmt.Errorf("sync: the source of %s has identical current and previous versions; rotate it at its provider first", name)
	}
	alreadySynced := true
	for _, tn := range tns {
		for _, env := range v.To[tn] {
			w, ok := e.State.Written(e.Targets[tn].ID(), env, name)
			if !ok || w.MAC != e.State.MAC(e.Targets[tn].ID(), env, name, next) {
				alreadySynced = false
			}
		}
	}
	if alreadySynced {
		return nil, fmt.Errorf("sync: the source of %s still holds the value last synced; rotate it at its provider first", name)
	}
	if prev == nil && !opt.NoRollback {
		return nil, fmt.Errorf("sync: the backend has no previous version of %s; a failed rotation could not be undone; pass --no-rollback to proceed", name)
	}

	var out []Entry
	wrote := []string{}
	failWith := func(tn, env string, cause error) ([]Entry, error) {
		out = append(out, Entry{tn, env, name, OutcomeFailed, cause.Error()})
		return append(out, e.rollback(ctx, v, wrote, prev)...), fmt.Errorf("%w: %s at %s/%s: %v", ErrRotateFailed, name, tn, env, cause)
	}
	for _, tn := range tns {
		c := e.Targets[tn]
		envs := v.To[tn]
		if err := c.Write(ctx, name, next, envs, v.IsSensitive()); err != nil {
			return failWith(tn, envs[0], err)
		}
		wrote = append(wrote, tn)
		if f, ok := c.(Flusher); ok {
			if err := f.Flush(ctx); err != nil {
				return failWith(tn, envs[0], err)
			}
		}
		for _, env := range envs {
			if err := e.audit(ctx, ActionWrite, map[string]any{"connection": v.From.Connection, "target": tn, "environment": env, "name": name, "outcome": "ok"}); err != nil {
				return out, err
			}
		}
	}
	for _, tn := range tns {
		c := e.Targets[tn]
		for _, env := range v.To[tn] {
			if err := e.verify(ctx, c, v, tn, env, next); err != nil {
				_ = e.audit(ctx, ActionRotateVerify, map[string]any{"connection": v.From.Connection, "target": tn, "environment": env, "name": name, "outcome": "failed"})
				return failWith(tn, env, err)
			}
			if err := e.audit(ctx, ActionRotateVerify, map[string]any{"connection": v.From.Connection, "target": tn, "environment": env, "name": name, "outcome": "ok"}); err != nil {
				return out, err
			}
			out = append(out, Entry{tn, env, name, OutcomeVerified, ""})
		}
	}
	if opt.KeepOld > 0 {
		sleep := e.Sleep
		if sleep == nil {
			sleep = sleepFor
		}
		if err := sleep(ctx, opt.KeepOld); err != nil {
			return out, err
		}
	}
	for _, tn := range tns {
		if err := e.recordOne(ctx, tn, v, next); err != nil {
			return out, err
		}
	}
	for _, tn := range tns {
		if err := e.audit(ctx, ActionRotateComplete, map[string]any{"connection": v.From.Connection, "target": tn, "environment": "", "name": name, "outcome": "ok"}); err != nil {
			return out, err
		}
	}
	return out, nil
}

func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (e *Engine) verify(ctx context.Context, c TargetClient, v Var, tn, env string, next []byte) error {
	rs, err := c.List(ctx)
	if err != nil {
		return err
	}
	var found *Remote
	for i := range rs {
		if rs[i].Name == v.Name && slices.Contains(rs[i].Environments, env) && !rs[i].Unmanaged {
			found = &rs[i]
		}
	}
	if found == nil {
		return errors.New("the entry is missing after the write")
	}
	if got, ok, err := c.Readback(ctx, *found); err != nil {
		return err
	} else if ok {
		if e.State.MAC(c.ID(), env, v.Name, got) != e.State.MAC(c.ID(), env, v.Name, next) {
			clear(got)
			return errors.New("the target holds a different value than was written")
		}
		clear(got)
	} else if w, had := e.State.Written(c.ID(), env, v.Name); had && !found.UpdatedAt.IsZero() && !found.UpdatedAt.After(w.RemoteAt) {
		return errors.New("the target did not report an update")
	}
	if v.Verify != nil && e.Probe != nil {
		if err := e.Probe(ctx, v.Verify.URL, next); err != nil {
			return fmt.Errorf("the verification request failed: %w", err)
		}
	}
	return nil
}

func (e *Engine) recordOne(ctx context.Context, tn string, v Var, val []byte) error {
	c := e.Targets[tn]
	rs, err := c.List(ctx)
	if err != nil {
		return err
	}
	for _, env := range v.To[tn] {
		if err := e.State.Record(c.ID(), env, v.Name, e.State.MAC(c.ID(), env, v.Name, val), e.updatedAt(rs, v.Name, env)); err != nil {
			return err
		}
	}
	return nil
}

// rollback writes prev back to every target that took the new value.
func (e *Engine) rollback(ctx context.Context, v Var, targets []string, prev []byte) []Entry {
	var out []Entry
	for _, tn := range targets {
		c := e.Targets[tn]
		envs := v.To[tn]
		if prev == nil {
			for _, env := range envs {
				out = append(out, Entry{tn, env, v.Name, OutcomeFailed, "no earlier value to restore"})
			}
			continue
		}
		err := c.Write(ctx, v.Name, prev, envs, v.IsSensitive())
		if f, ok := c.(Flusher); ok && err == nil {
			err = f.Flush(ctx)
		}
		if err == nil {
			err = e.recordOne(ctx, tn, v, prev)
		}
		for _, env := range envs {
			en := Entry{tn, env, v.Name, OutcomeRolledBack, ""}
			outcome := "ok"
			if err != nil {
				en.Outcome, en.Error, outcome = OutcomeFailed, err.Error(), "failed"
			}
			_ = e.audit(ctx, ActionRotateRollback, map[string]any{"connection": v.From.Connection, "target": tn, "environment": env, "name": v.Name, "outcome": outcome})
			out = append(out, en)
		}
	}
	return out
}
