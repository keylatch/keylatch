package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/registry"
)

// Where a decided child runs.
const (
	childInCaller = "caller"
	childInDaemon = "daemon"
)

// decision is what one socket decision records. It holds names, digests and
// counts only.
type decision struct {
	op         string
	verb       string
	connection string
	tier       Tier
	child      string
	res        callerkind.Result
	argv       []string
	cwd        string
	hosts      []string
	runID      string
	reason     string
}

func digest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// record writes the run.decided event for d. Without an audit emitter it does
// nothing.
func (s *Server) record(ctx context.Context, d decision, outcome audit.Outcome) error {
	if s.cfg.Audit == nil {
		return nil
	}
	extra := map[string]any{
		"op":          d.op,
		"caller_kind": string(d.res.Kind),
	}
	set := func(k, v string) {
		if v != "" {
			extra[k] = v
		}
	}
	set("verb", d.verb)
	set("connection", d.connection)
	set("tier", string(d.tier))
	set("child_location", d.child)
	set("harness", d.res.Harness)
	set("run_id", d.runID)
	set("reason", d.reason)
	if len(d.argv) > 0 {
		extra["argv_sha256"] = digest(d.argv...)
	}
	if d.cwd != "" {
		extra["cwd_sha256"] = digest(d.cwd)
	}
	if len(d.hosts) > 0 {
		extra["hosts"] = d.hosts
	}
	return s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionRunDecided, Outcome: outcome, Extra: extra})
}

func (s *Server) recordExit(ctx context.Context, op, verb, runID string, exit int, started time.Time, bytes int64, reason string) {
	if s.cfg.Audit == nil {
		return
	}
	extra := map[string]any{
		"run_id":        runID,
		"op":            op,
		"exit":          exit,
		"duration_ms":   time.Since(started).Milliseconds(),
		"bytes_relayed": bytes,
	}
	if verb != "" {
		extra["verb"] = verb
	}
	if reason != "" {
		extra["reason"] = reason
	}
	outcome := audit.OutcomeOK
	if exit != 0 {
		outcome = audit.OutcomeError
	}
	_ = s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionRunExited, Outcome: outcome, Extra: extra})
}

func auditRefusal(resp Response, err error) Response {
	resp.OK, resp.Session, resp.Credential = false, nil, nil
	resp.Code, resp.ExitCode = CodeRefused, exitcode.SecurityBlock
	resp.Error = fmt.Sprintf("the audit log cannot record this decision (%v); Keylatch does not act without an audit trail", err)
	return resp
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// runState tracks a decided run until its client reports the exit.
type runState struct {
	id      string
	started time.Time
	bytes   atomic.Int64
	// revoke ends the gateway token issued for the run; nil when none was.
	revoke func()
}

func (r *runState) end() {
	if r.revoke != nil {
		r.revoke()
	}
}

// relayed counts bytes moved for the run; a nil run counts nothing.
func (r *runState) relayed(n int) {
	if r != nil && n > 0 {
		r.bytes.Add(int64(n))
	}
}

type runTable struct {
	mu   sync.Mutex
	runs map[string]*runState
}

func (t *runTable) get(id string) *runState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runs[id]
}

func (t *runTable) take(id string) *runState {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.runs[id]
	delete(t.runs, id)
	return r
}

// add registers a run and returns the runs whose client never reported an
// exit within twice the session lifetime.
func (t *runTable) add(r *runState) (expired []*runState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.runs == nil {
		t.runs = map[string]*runState{}
	}
	for id, old := range t.runs {
		if time.Since(old.started) > 2*sessionTTL {
			expired = append(expired, old)
			delete(t.runs, id)
		}
	}
	t.runs[r.id] = r
	return expired
}

// decideRun answers a session request and records the decision. A decision
// that cannot be recorded is refused.
func (s *Server) decideRun(ctx context.Context, res callerkind.Result, rr *RunRequest) Response {
	var revoke func()
	resp := s.runSession(ctx, res.Kind, rr, &revoke)
	d := decision{op: string(OpRunSession), res: res, child: childInCaller}
	if rr != nil {
		d.connection, d.argv, d.cwd, d.tier = rr.Connection, rr.Command, rr.CWD, rr.Tier
		if tmpl, err := registry.Get(rr.Connection); err == nil {
			if b, ok := tmpl.Binding(); ok {
				d.hosts = b.Hosts
			}
		}
		if d.tier == "" {
			d.tier = s.preferredTier(rr)
		}
	}
	outcome := audit.OutcomeOK
	if resp.OK && resp.Session != nil {
		d.tier = resp.Session.Tier
		d.runID = newRunID()
		resp.Session.RunID = d.runID
	} else {
		outcome, d.reason = audit.OutcomeDenied, resp.Error
	}
	if err := s.record(ctx, d, outcome); err != nil {
		s.abandon(resp)
		(&runState{revoke: revoke}).end()
		return auditRefusal(Response{Kind: res.Kind}, err)
	}
	if d.runID != "" {
		for _, old := range s.runs.add(&runState{id: d.runID, started: time.Now(), revoke: revoke}) {
			old.end()
			s.recordExit(ctx, d.op, "", old.id, -1, old.started, old.bytes.Load(), "expired")
		}
	} else {
		(&runState{revoke: revoke}).end()
	}
	return resp
}

// abandon closes whatever an unrecorded session opened.
func (s *Server) abandon(resp Response) {
	if resp.Session == nil || resp.Session.ProxyID == "" || s.cfg.Placeholders == nil {
		return
	}
	if sess, ok := s.cfg.Placeholders.Get(resp.Session.ProxyID); ok {
		sess.Close("audit_unavailable")
	}
}

func (s *Server) runExited(ctx context.Context, req Request) Response {
	r := s.runs.take(req.RunID)
	if r == nil {
		return Response{Code: CodeNotFound, ExitCode: exitcode.Missing, Error: "no such run"}
	}
	r.end()
	s.recordExit(ctx, string(OpRunSession), "", r.id, req.Exit, r.started, r.bytes.Load(), "")
	return Response{OK: true}
}
