package sync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

var canaryValue = "canary" + "-sync-" + "b83e"

type memEntry struct {
	Remote
	value string
}

// memTarget behaves like a Vercel project: an upsert replaces the entry with
// the same name and environments and otherwise adds one.
type memTarget struct {
	id        string
	entries   []*memEntry
	clock     time.Time
	writes    int
	deletes   int
	flushes   int
	failWrite string
	hideValue bool
	frozen    bool
}

func (m *memTarget) ID() string { return m.id }

func (m *memTarget) List(context.Context) ([]Remote, error) {
	var out []Remote
	for _, e := range m.entries {
		out = append(out, e.Remote)
	}
	return out, nil
}

func (m *memTarget) tick() time.Time {
	if !m.frozen {
		m.clock = m.clock.Add(time.Second)
	}
	return m.clock
}

func (m *memTarget) Write(_ context.Context, name string, value []byte, envs []string, sensitive bool) error {
	if m.failWrite == string(value) {
		return errors.New("target refused the write")
	}
	m.writes++
	typ := "encrypted"
	if sensitive {
		typ = "sensitive"
	}
	for _, e := range m.entries {
		if e.Name == name && sameSet(e.Environments, envs) {
			e.value, e.Type, e.UpdatedAt = string(value), typ, m.tick()
			return nil
		}
	}
	m.entries = append(m.entries, &memEntry{Remote: Remote{ID: fmt.Sprintf("id%d", len(m.entries)+1), Name: name, Environments: slices.Clone(envs), Type: typ, UpdatedAt: m.tick()}, value: string(value)})
	return nil
}

func (m *memTarget) Delete(_ context.Context, r Remote) error {
	m.deletes++
	for i, e := range m.entries {
		if e.ID == r.ID {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return nil
		}
	}
	return errors.New("no such entry")
}

func (m *memTarget) Readback(_ context.Context, r Remote) ([]byte, bool, error) {
	if m.hideValue || r.Type != "encrypted" {
		return nil, false, nil
	}
	for _, e := range m.entries {
		if e.ID == r.ID {
			return []byte(e.value), true, nil
		}
	}
	return nil, false, errors.New("no such entry")
}

func (m *memTarget) Flush(context.Context) error { m.flushes++; return nil }

func (m *memTarget) value(name, env string) string {
	for _, e := range m.entries {
		if e.Name == name && slices.Contains(e.Environments, env) {
			return e.value
		}
	}
	return ""
}

type memSecrets struct {
	values map[string]string
	prev   map[string]string
	reads  int
}

func (s *memSecrets) key(c, f string) string { return c + "/" + f }

func (s *memSecrets) Value(_ context.Context, c, f string) ([]byte, error) {
	s.reads++
	v, ok := s.values[s.key(c, f)]
	if !ok {
		return nil, errors.New("no such connection")
	}
	return []byte(v), nil
}

func (s *memSecrets) Snapshot(ctx context.Context, c, f string) (SourceSnapshot, error) {
	current, err := s.Value(ctx, c, f)
	if err != nil {
		return SourceSnapshot{}, err
	}
	var previous []byte
	if value, ok := s.prev[s.key(c, f)]; ok {
		previous = []byte(value)
	}
	return SourceSnapshot{Path: s.key(c, f), Version: 2, PreviousVersion: 1, Current: current, Previous: previous}, err
}

type memState struct {
	key []byte
	m   map[string]Written
}

func (s *memState) Written(id, env, name string) (Written, bool) {
	w, ok := s.m[id+"|"+env+"|"+name]
	return w, ok
}

func (s *memState) MAC(id, env, name string, v []byte) string {
	h := hmac.New(sha256.New, s.key)
	for _, p := range []string{id, env, name} {
		fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	h.Write(v)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *memState) Record(id, env, name, mac string, at time.Time) error {
	s.m[id+"|"+env+"|"+name] = Written{MAC: mac, RemoteAt: at}
	return nil
}

func (s *memState) Forget(id, env, name string) error {
	delete(s.m, id+"|"+env+"|"+name)
	return nil
}

type auditLog struct {
	events []map[string]any
	fail   bool
}

func (a *auditLog) Event(_ context.Context, action string, f map[string]any) error {
	if a.fail {
		return errors.New("audit unavailable")
	}
	e := map[string]any{"action": action}
	for k, v := range f {
		e[k] = v
	}
	a.events = append(a.events, e)
	return nil
}

func (a *auditLog) count(action string) int {
	n := 0
	for _, e := range a.events {
		if e["action"] == action {
			n++
		}
	}
	return n
}

type rig struct {
	e       *Engine
	web, ci *memTarget
	sec     *memSecrets
	st      *memState
	audit   *auditLog
}

const rigManifest = `version: 1
targets:
  web: {type: vercel, project: prj_1, credential: vercel-deploy}
  ci:  {type: github-actions, repo: owner/app, environments: [production], credential: gh}
vars:
  - name: DATABASE_URL
    from: {connection: app-db, field: url}
    to: {web: [production, preview], ci: [repository]}
  - name: API_KEY
    from: {connection: api}
    to: {web: [production]}
    verify: {url: "https://probe.example.test/ok"}
`

func newRig(t *testing.T) *rig {
	t.Helper()
	m, err := Parse([]byte(rigManifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{
		web:   &memTarget{id: "vercel:prj_1", clock: time.Unix(1_700_000_000, 0)},
		ci:    &memTarget{id: "github:owner/app", clock: time.Unix(1_700_000_000, 0)},
		sec:   &memSecrets{values: map[string]string{"app-db/url": canaryValue + "-db", "api/": canaryValue + "-api"}, prev: map[string]string{}},
		st:    &memState{key: []byte("sync-key-for-tests-0123456789abcd"), m: map[string]Written{}},
		audit: &auditLog{},
	}
	r.e = &Engine{
		Manifest: m, Targets: map[string]TargetClient{"web": r.web, "ci": r.ci},
		Secrets: r.sec, State: r.st, Audit: r.audit,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return r
}

func kinds(cs []Change) map[string]int { return Counts(cs) }

func TestSyncApplyIdempotent(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	res, err := r.e.Apply(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	written := 0
	for _, en := range res {
		if en.Outcome == OutcomeWritten {
			written++
		}
	}
	if written != 4 || r.web.value("DATABASE_URL", "preview") != canaryValue+"-db" || r.ci.value("DATABASE_URL", "repository") != canaryValue+"-db" {
		t.Fatalf("first apply wrote %d: %+v", written, res)
	}
	writes := r.web.writes + r.ci.writes
	res, err = r.e.Apply(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.web.writes+r.ci.writes != writes {
		t.Fatalf("the second apply wrote again: %+v", res)
	}
	for _, en := range res {
		if en.Outcome != OutcomeUnchanged {
			t.Fatalf("outcome %+v", en)
		}
	}
	if r.web.flushes == 0 {
		t.Fatal("a buffering target must be flushed")
	}
}

func TestSyncDiffNamesOnly(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cs, err := r.e.Diff(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(cs); k[KindAdd] != 4 || len(cs) != 4 {
		t.Fatalf("empty targets: %v", cs)
	}
	if r.sec.reads != 0 {
		t.Fatal("drift mode read a source")
	}
	if _, err := r.e.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	cs, _ = r.e.Diff(ctx, true)
	b, _ := json.Marshal(cs)
	for _, leak := range []string{canaryValue, "-db", "-api"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("diff output contains %q: %s", leak, b)
		}
	}
	if Drifted(cs) {
		t.Fatalf("drift after apply: %v", cs)
	}
}

func TestSyncDiffDetectsValueChangeByHMAC(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	_, _ = r.e.Apply(ctx, false)
	r.sec.values["app-db/url"] = canaryValue + "-rotated"
	cs, err := r.e.Diff(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cs {
		if c.Kind == KindUpdate {
			got = append(got, c.Target+"/"+c.Environment+"/"+c.Name+": "+c.Reason)
		}
	}
	want := []string{"ci/repository/DATABASE_URL: " + ReasonSource, "web/preview/DATABASE_URL: " + ReasonSource, "web/production/DATABASE_URL: " + ReasonSource}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("updates = %v", got)
	}
	// Drift mode cannot see a value change, by design.
	cs, _ = r.e.Diff(ctx, false)
	if Drifted(cs) {
		t.Fatalf("drift without reading values reported %v", cs)
	}
}

func TestSyncDiffChangedOutsideKeylatch(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	_, _ = r.e.Apply(ctx, false)
	// Someone edits the entry in the dashboard: the value is the same, the time is newer.
	r.web.entries[0].UpdatedAt = r.web.entries[0].UpdatedAt.Add(time.Hour)
	cs, _ := r.e.Diff(ctx, true)
	found := false
	for _, c := range cs {
		if c.Kind == KindUpdate && c.Reason == ReasonOutside {
			found = true
		}
	}
	if !found {
		t.Fatalf("no outside change in %v", cs)
	}
	// An entry keylatch never wrote is reported too.
	r.web.entries = append(r.web.entries, &memEntry{Remote: Remote{ID: "x", Name: "API_KEY", Environments: []string{"production"}, Type: "sensitive"}})
	r.web.entries = slices.DeleteFunc(r.web.entries, func(e *memEntry) bool { return e.ID != "x" && e.Name == "API_KEY" })
	r.st.Forget(r.web.id, "production", "API_KEY")
	cs, _ = r.e.Diff(ctx, true)
	for _, c := range cs {
		if c.Name == "API_KEY" && c.Reason != ReasonUnknown {
			t.Fatalf("hand-made entry: %+v", c)
		}
	}
}

func TestSyncDriftExitCodes(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cs, _ := r.e.Diff(ctx, false)
	if !Drifted(cs) {
		t.Fatal("missing names are drift")
	}
	_, _ = r.e.Apply(ctx, false)
	cs, _ = r.e.Diff(ctx, false)
	if Drifted(cs) {
		t.Fatalf("clean targets drifted: %v", cs)
	}
	r.web.entries = append(r.web.entries, &memEntry{Remote: Remote{ID: "extra", Name: "STRAY", Environments: []string{"production"}, Type: "encrypted"}},
		&memEntry{Remote: Remote{ID: "branch", Name: "BRANCHED", Environments: []string{"preview"}, Unmanaged: true}})
	cs, _ = r.e.Diff(ctx, false)
	if k := kinds(cs); k[KindExtra] != 1 || !Drifted(cs) {
		t.Fatalf("an extra name must be drift, and an unmanaged one must not: %v", cs)
	}
	for _, c := range cs {
		if c.Name == "BRANCHED" {
			t.Fatal("an unmanaged entry is neither managed nor extra")
		}
	}
}

func TestSyncPrune(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	_, _ = r.e.Apply(ctx, false)
	r.web.entries = append(r.web.entries, &memEntry{Remote: Remote{ID: "extra", Name: "STRAY", Environments: []string{"production", "preview"}, Type: "encrypted"}},
		&memEntry{Remote: Remote{ID: "branch", Name: "BRANCHED", Environments: []string{"preview"}, Unmanaged: true}})
	res, err := r.e.Apply(ctx, false)
	if err != nil || r.web.deletes != 0 {
		t.Fatalf("apply without prune deleted: %v %d", err, r.web.deletes)
	}
	_ = res
	res, err = r.e.Apply(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	deleted := 0
	for _, en := range res {
		if en.Outcome == OutcomeDeleted && en.Name == "STRAY" {
			deleted++
		}
	}
	if deleted != 2 || r.web.deletes != 1 || r.audit.count(ActionDelete) != 2 {
		t.Fatalf("prune: %d entries deleted, %d deletes, %d events", deleted, r.web.deletes, r.audit.count(ActionDelete))
	}
	for _, e := range r.web.entries {
		if e.Name == "STRAY" {
			t.Fatal("STRAY survived")
		}
		if e.Name == "BRANCHED" {
			continue
		}
	}
	if !slices.ContainsFunc(r.web.entries, func(e *memEntry) bool { return e.Name == "BRANCHED" }) {
		t.Fatal("an unmanaged entry was pruned")
	}
}

func TestSyncVercelReshapeDeletesAfterWrite(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	// The variable exists for production only, as encrypted; the manifest now wants production and preview, sensitive.
	r.web.entries = []*memEntry{{Remote: Remote{ID: "old", Name: "DATABASE_URL", Environments: []string{"production"}, Type: "encrypted", UpdatedAt: time.Unix(1_600_000_000, 0)}, value: "old"}}
	var order []string
	wrapped := &orderTarget{memTarget: r.web, log: &order}
	r.e.Targets["web"] = wrapped
	if _, err := r.e.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	wi, di := slices.Index(order, "write DATABASE_URL"), slices.Index(order, "delete old")
	if wi < 0 || di < 0 || di < wi {
		t.Fatalf("the old entry must be deleted after the new one is written: %v", order)
	}
	var shapes []string
	for _, e := range r.web.entries {
		if e.Name == "DATABASE_URL" {
			shapes = append(shapes, e.Type+":"+strings.Join(e.Environments, ","))
		}
	}
	if len(shapes) != 1 || shapes[0] != "sensitive:production,preview" {
		t.Fatalf("entries = %v", shapes)
	}
}

type orderTarget struct {
	*memTarget
	log *[]string
}

func (o *orderTarget) Write(ctx context.Context, name string, v []byte, envs []string, s bool) error {
	*o.log = append(*o.log, "write "+name)
	return o.memTarget.Write(ctx, name, v, envs, s)
}

func (o *orderTarget) Delete(ctx context.Context, r Remote) error {
	*o.log = append(*o.log, "delete "+r.ID)
	return o.memTarget.Delete(ctx, r)
}

func TestSyncAuditOneEventPerWriteNoValue(t *testing.T) {
	r := newRig(t)
	if _, err := r.e.Apply(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := r.audit.count(ActionWrite); got != 4 {
		t.Fatalf("%d write events for 4 entries", got)
	}
	b, _ := json.Marshal(r.audit.events)
	if strings.Contains(string(b), canaryValue) || strings.Contains(strings.ToLower(string(b)), "mac") {
		t.Fatalf("audit holds a value or a hash: %s", b)
	}
	r2 := newRig(t)
	r2.audit.fail = true
	if _, err := r2.e.Apply(context.Background(), false); err == nil {
		t.Fatal("an unavailable audit log must stop the apply")
	}
}

func TestSyncApplyReportsFailures(t *testing.T) {
	r := newRig(t)
	r.web.failWrite = canaryValue + "-db"
	res, err := r.e.Apply(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, en := range res {
		if en.Outcome == OutcomeFailed {
			failed++
			if strings.Contains(en.Error, canaryValue) {
				t.Fatal("an error holds a value")
			}
		}
	}
	if failed != 2 {
		t.Fatalf("failed = %d: %+v", failed, res)
	}
	delete(r.sec.values, "api/")
	if _, err := r.e.Apply(context.Background(), false); err == nil {
		t.Fatal("an unreadable source must stop the apply before any write")
	}
	fresh := newRig(t)
	delete(fresh.sec.values, "api/")
	res, err = fresh.e.Apply(context.Background(), false)
	if err != nil || !slices.ContainsFunc(res, func(en Entry) bool { return en.Name == "API_KEY" && en.Outcome == OutcomeFailed }) {
		t.Fatalf("an unreadable source must fail its entries: %v %+v", err, res)
	}
}

func rotateRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	if _, err := r.e.Apply(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.sec.values["app-db/url"] = canaryValue + "-v2"
	r.sec.prev["app-db/url"] = canaryValue + "-db"
	r.sec.prev["api/"] = canaryValue + "-api"
	return r
}

func TestSyncRotateVerifiesBeforeCompletion(t *testing.T) {
	r := rotateRig(t)
	var probed []string
	r.e.Probe = func(_ context.Context, url string, _ []byte) error { probed = append(probed, url); return nil }
	var slept time.Duration
	r.e.Sleep = func(_ context.Context, d time.Duration) error { slept = d; return nil }
	res, err := r.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{KeepOld: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if r.web.value("DATABASE_URL", "production") != canaryValue+"-v2" || r.ci.value("DATABASE_URL", "repository") != canaryValue+"-v2" {
		t.Fatal("not every target holds the new value")
	}
	if got := r.sec.prev["app-db/url"]; got != canaryValue+"-db" {
		t.Fatal("rotation changed the source's version history")
	}
	if slept != time.Minute {
		t.Fatalf("keep-old wait = %v", slept)
	}
	verified := 0
	for _, en := range res {
		if en.Outcome == OutcomeVerified {
			verified++
		}
	}
	if verified != 3 || r.audit.count(ActionRotateVerify) != 3 || r.audit.count(ActionRotateComplete) != 2 {
		t.Fatalf("verified %d, verify events %d, complete events %d", verified, r.audit.count(ActionRotateVerify), r.audit.count(ActionRotateComplete))
	}
	cs, _ := r.e.Diff(context.Background(), true)
	if Drifted(cs) {
		t.Fatalf("drift after a rotation: %v", cs)
	}

	r.sec.values["api/"] = canaryValue + "-api2"
	if _, err := r.e.Rotate(context.Background(), "API_KEY", RotateOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(probed) != 1 || probed[0] != "https://probe.example.test/ok" {
		t.Fatalf("probes = %v", probed)
	}
}

func TestSyncRotateRollbackOnVerifyFailure(t *testing.T) {
	r := rotateRig(t)
	r.e.Probe = func(context.Context, string, []byte) error { return errors.New("401") }
	r.sec.values["api/"] = canaryValue + "-api2"
	r.sec.prev["api/"] = canaryValue + "-api"
	res, err := r.e.Rotate(context.Background(), "API_KEY", RotateOptions{})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatalf("err = %v", err)
	}
	if r.web.value("API_KEY", "production") != canaryValue+"-api" {
		t.Fatal("the previous value was not written back")
	}
	if r.sec.prev["api/"] != canaryValue+"-api" {
		t.Fatal("a failed rotation must not retire the old value")
	}
	if r.audit.count(ActionRotateRollback) != 1 || r.audit.count(ActionRotateComplete) != 0 {
		t.Fatalf("events: rollback %d complete %d", r.audit.count(ActionRotateRollback), r.audit.count(ActionRotateComplete))
	}
	if !slices.ContainsFunc(res, func(en Entry) bool { return en.Outcome == OutcomeRolledBack }) {
		t.Fatalf("no rollback entry: %+v", res)
	}
	cs, _ := r.e.Diff(context.Background(), false)
	for _, c := range cs {
		if c.Name == "API_KEY" && c.Kind != KindUnchanged {
			t.Fatalf("after a rollback the record must match the target: %+v", c)
		}
	}
}

func TestSyncRotateVerifiesByReadbackAndUpdateTime(t *testing.T) {
	r := rotateRig(t)
	// A target that silently drops the write: the readback shows the old value.
	r.web.frozen = true
	r.web.failWrite = ""
	stale := &staleTarget{memTarget: r.web}
	r.e.Targets["web"] = stale
	_, err := r.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{})
	if !errors.Is(err, ErrRotateFailed) {
		t.Fatalf("a target that kept the old value verified: %v", err)
	}
	if r.ci.value("DATABASE_URL", "repository") != canaryValue+"-db" {
		t.Fatal("the target that did take the new value must be rolled back")
	}

	// A write-only target that reports no newer update time fails the update-time check.
	r2 := rotateRig(t)
	r2.ci.frozen, r2.ci.hideValue = true, true
	r2.web.hideValue = true
	r2.ci.entries[0].UpdatedAt = time.Unix(1_700_000_000, 0).Add(-time.Hour)
	r2.st.m[r2.ci.id+"|repository|DATABASE_URL"] = Written{MAC: "x", RemoteAt: time.Unix(1_700_000_100, 0)}
	if _, err := r2.e.Rotate(context.Background(), "DATABASE_URL", RotateOptions{Target: "ci"}); !errors.Is(err, ErrRotateFailed) {
		t.Fatalf("a stale update time verified: %v", err)
	}
}

type staleTarget struct{ *memTarget }

func (s *staleTarget) Write(ctx context.Context, name string, v []byte, envs []string, sens bool) error {
	return nil
}

func TestSyncRotateRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.e.Rotate(ctx, "NOPE", RotateOptions{}); err == nil {
		t.Fatal("unknown variable")
	}
	if _, err := r.e.Rotate(ctx, "API_KEY", RotateOptions{Target: "ci"}); err == nil {
		t.Fatal("variable has no such target")
	}
	if _, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{}); err == nil || !strings.Contains(err.Error(), "--no-rollback") {
		t.Fatalf("no earlier value: %v", err)
	}
	if r.web.writes != 0 {
		t.Fatal("a refused rotation wrote")
	}
	_, _ = r.e.Apply(ctx, false)
	if _, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{}); err == nil || !strings.Contains(err.Error(), "still holds") {
		t.Fatalf("an unchanged source: %v", err)
	}
	r.sec.values["app-db/url"] = canaryValue + "-v3"
	delete(r.sec.prev, "app-db/url")
	if _, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{NoRollback: true}); err != nil {
		t.Fatalf("--no-rollback must allow it: %v", err)
	}
	r.sec.values["app-db/url"] = canaryValue + "-v4"
	r.sec.prev["app-db/url"] = canaryValue + "-v3"
	r.web.failWrite = canaryValue + "-v4"
	if _, err := r.e.Rotate(ctx, "DATABASE_URL", RotateOptions{}); !errors.Is(err, ErrRotateFailed) {
		t.Fatalf("a refused write: %v", err)
	}
}

func TestSleepFor(t *testing.T) {
	if err := sleepFor(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepFor(ctx, time.Hour); err == nil {
		t.Fatal("a cancelled wait returned nil")
	}
}
