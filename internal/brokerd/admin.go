package brokerd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
)

// admin serves the broker operations of one partition.
type admin struct {
	s *Server
	p *partition
}

// Handle implements control.Extension.
func (a *admin) Handle(ctx context.Context, conn control.Conn, peer control.Peer, res callerkind.Result, raw []byte) bool {
	if _, ok := brokerapi.OpOf(raw); !ok {
		return false
	}
	var resp brokerapi.Response
	if req, err := brokerapi.Decode(raw); err != nil {
		resp = fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	} else if req.Op == brokerapi.OpPresenceHelper {
		a.serveHelper(ctx, conn, peer, res)
		return true
	} else if req.Op == brokerapi.OpApprovalDecide {
		requestCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		// Decisions have no further client frames; disconnects cancel the OS prompt.
		go func() {
			var extra [1]byte
			_, _ = conn.Read(extra[:])
			cancel()
			close(done)
		}()
		resp = a.dispatch(requestCtx, peer, res, req)
		cancel()
		_ = conn.SetReadDeadline(time.Now())
		<-done
	} else {
		resp = a.dispatch(context.WithValue(ctx, connCtxKey{}, conn), peer, res, req)
	}
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
	return true
}

// serveHelper keeps the connection as the user's presence helper. Agents never
// get here: a helper that an agent could register would let it intercept the
// challenges meant for the human.
func (a *admin) serveHelper(ctx context.Context, conn control.Conn, peer control.Peer, res callerkind.Result) {
	reply := func(r brokerapi.Response) {
		b, _ := json.Marshal(r)
		_, _ = conn.Write(append(b, '\n'))
	}
	switch {
	case a.s.cfg.Helpers == nil:
		reply(fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, errors.New("this broker has no presence helper support")))
		return
	case res.Kind == callerkind.Agent:
		_ = a.emit(ctx, audit.ActionPresenceDecision, audit.OutcomeDenied, res, map[string]any{"operation": "presence.helper", "result": "refused", "reason": "agent session"})
		reply(fail(brokerapi.CodeRefused, exitcode.SecurityBlock, ErrAgentPresence))
		return
	}
	if v := a.s.cfg.HelperAdmit; v != nil {
		if err := v(ctx, peer); err != nil {
			_ = a.emit(ctx, audit.ActionPresenceDecision, audit.OutcomeDenied, res, map[string]any{"operation": "presence.helper", "result": "refused", "reason": err.Error()})
			reply(fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err))
			return
		}
	}
	reply(brokerapi.Response{OK: true})
	a.s.cfg.Helpers.Serve(peer.UID, conn)
}

func fail(code string, exit int, err error) brokerapi.Response {
	return brokerapi.Response{Code: code, ExitCode: exit, Error: err.Error()}
}

func (a *admin) emit(ctx context.Context, action audit.Action, outcome audit.Outcome, res callerkind.Result, extra map[string]any) error {
	if extra == nil {
		extra = map[string]any{}
	}
	extra["caller_kind"] = string(res.Kind)
	return a.s.cfg.Audit.Emit(ctx, audit.Event{Action: action, Outcome: outcome, Extra: extra})
}

// dispatch answers one decoded request. A privileged request is served only
// with a proof issued for exactly that request, so a client that skips the
// presence step gets a refusal no matter what it sends.
func (a *admin) dispatch(ctx context.Context, peer control.Peer, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	if brokerapi.Privileged(req.Op) {
		if resp, ok := a.authorize(ctx, peer, res, req); !ok {
			return resp
		}
	}
	switch req.Op {
	case brokerapi.OpApprovalList:
		return a.listApprovals(ctx, peer, res)
	case brokerapi.OpApprovalDecide:
		return a.decideApproval(ctx, peer, res, req)
	case brokerapi.OpStatus:
		return a.status(ctx)
	case brokerapi.OpPresenceBegin:
		proof, err := a.s.presence.Begin(ctx, subjectOf(peer.PID, peer.Start, peer.UID), res, *req.Target)
		if err != nil {
			return presenceFailure(err)
		}
		return brokerapi.Response{OK: true, Proof: &proof}
	case brokerapi.OpSecretSet:
		return a.setSecret(ctx, res, req)
	case brokerapi.OpSecretDelete:
		return a.deleteSecret(ctx, res, req)
	case brokerapi.OpSecretList:
		return a.listSecrets(ctx)
	case brokerapi.OpPolicyCheck:
		st := a.p.policy.Verify()
		return brokerapi.Response{OK: true, Policy: &st}
	case brokerapi.OpPolicyExport:
		b, err := a.p.policy.Export()
		if err != nil {
			return fail(brokerapi.CodeRefused, exitcode.PolicyDeny, err)
		}
		return brokerapi.Response{OK: true, Bundle: &b}
	case brokerapi.OpPolicyAccept:
		return a.changePolicy(ctx, res, req, func() error { return a.p.policy.Accept(req.Files, req.Digest()) })
	case brokerapi.OpPolicyImport:
		return a.changePolicy(ctx, res, req, func() error { return a.p.policy.Import(*req.Bundle, req.Digest()) })
	case brokerapi.OpAuditHead:
		if a.s.cfg.AuditHead == nil {
			return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, errors.New("the audit head is not available"))
		}
		h := a.s.cfg.AuditHead()
		return brokerapi.Response{OK: true, Head: &brokerapi.AuditHead{Hash: h.Hash, Events: h.Seq}}
	case brokerapi.OpMigrateImport, brokerapi.OpMigrateSources:
		return a.migrateIn(ctx, res, req)
	case brokerapi.OpMigrateExport:
		return a.migrateOut(ctx, res)
	case brokerapi.OpRotateKeys:
		return a.rotate(ctx, res)
	case brokerapi.OpSessionRegister:
		ticket, err := a.s.sessions.Register(peer.UID, req.Session.ID, req.Session.Cgroup)
		if err != nil {
			return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
		}
		start, _ := strconv.ParseUint(peer.Start, 10, 64)
		l := Launcher{PID: peer.PID, Start: start}
		a.s.sessions.Bind(peer.UID, req.Session.ID, l)
		return brokerapi.Response{OK: true, Session: &brokerapi.SessionInfo{ID: req.Session.ID, Ticket: ticket, PID: l.PID, Start: l.Start}}
	case brokerapi.OpSessionEnd:
		a.s.sessions.End(peer.UID, req.Session.ID)
		return brokerapi.Response{OK: true}
	case brokerapi.OpSyncDiff, brokerapi.OpSyncDrift, brokerapi.OpSyncApply, brokerapi.OpSyncRotate:
		return a.syncOp(ctx, peer, res, req)
	case brokerapi.OpServiceEnroll:
		return a.enrollService(ctx, res, req)
	case brokerapi.OpServiceRevoke:
		return a.revokeService(ctx, res, req)
	case brokerapi.OpServiceList:
		return a.listServices(ctx)
	case brokerapi.OpServiceRelease:
		return a.s.releaseService(ctx, peer.UID, peer.Cgroup, res, req)
	case brokerapi.OpMachineIssue:
		return a.issueMachine(ctx, res, req)
	case brokerapi.OpMachineRevoke:
		return a.revokeMachine(ctx, res, req)
	case brokerapi.OpMachineList:
		return a.listMachines()
	case brokerapi.OpMachineListen:
		return a.setMachineListen(ctx, res, req)
	case brokerapi.OpSessionVerify:
		l, ok := a.s.sessions.Lookup(req.Ticket, peer.UID)
		if !ok {
			return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, errors.New("the ticket is not valid"))
		}
		return brokerapi.Response{OK: true, Session: &brokerapi.SessionInfo{PID: l.PID, Start: l.Start}}
	}
	return fail(brokerapi.CodeBadRequest, exitcode.UserError, errors.New("unknown operation"))
}

func presenceFailure(err error) brokerapi.Response {
	switch {
	case errors.Is(err, ErrAgentPresence):
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	case errors.Is(err, ErrPresenceUnavailable):
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	return fail(brokerapi.CodePresenceRequired, exitcode.SecurityBlock, err)
}

// authorize decides whether a privileged request may proceed. An agent never
// may; everyone else needs a proof for this request.
func (a *admin) authorize(ctx context.Context, peer control.Peer, res callerkind.Result, req brokerapi.Request) (brokerapi.Response, bool) {
	action, _ := req.Describe()
	if res.Kind == callerkind.Agent {
		_ = a.s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionSecurityBlock, Outcome: audit.OutcomeDenied, Extra: map[string]any{
			"command": string(req.Op), "signals": res.Reasons, "caller_kind": string(res.Kind),
		}})
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, errors.New("an agent session cannot make privileged requests")), false
	}
	if err := a.s.presence.Require(peer.UID, req); err != nil {
		reason := err.Error()
		_ = a.s.cfg.Audit.Emit(ctx, audit.Event{Action: audit.ActionPresenceDecision, Outcome: audit.OutcomeDenied, Extra: map[string]any{
			"operation": action, "method": a.s.presence.MethodName(), "result": "refused", "digest": req.Digest(), "caller_kind": string(res.Kind), "reason": reason,
		}})
		resp := presenceFailure(err)
		if errors.Is(err, ErrPresenceRequired) || errors.Is(err, ErrProofInvalid) || errors.Is(err, ErrProofExpired) {
			resp.Code = brokerapi.CodePresenceRequired
		}
		return resp, false
	}
	return brokerapi.Response{}, true
}

func (a *admin) status(ctx context.Context) brokerapi.Response {
	n := 0
	if entries, err := a.p.store.List(ctx, ""); err == nil {
		n = len(entries)
	}
	return brokerapi.Response{OK: true, Status: &brokerapi.Status{
		Version: a.s.cfg.Version, Mode: "broker", UID: a.p.uid, KeyID: a.s.cfg.Keys.KeyID(),
		KeysLocked: a.s.cfg.Keys.Locked(), RotationPending: a.s.cfg.Keys.Pending(),
		Policy: a.p.policy.Verify().State, Secrets: n, Presence: a.s.presence.MethodName(),
	}}
}

func (a *admin) setSecret(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	if _, err := a.p.store.Put(ctx, req.Path, req.Value); err != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	if err := a.emit(ctx, audit.ActionSet, audit.OutcomeOK, res, map[string]any{"connection": req.Path, "backend": "broker"}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true}
}

func (a *admin) deleteSecret(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	entries, err := a.p.store.List(ctx, req.Path)
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if !slices.ContainsFunc(entries, func(e backend.Entry) bool { return e.Path == req.Path }) {
		// Nothing to delete: the store says why (a bad path or no such secret).
		if err := a.p.store.Delete(ctx, req.Path); err != nil && !errors.Is(err, backend.ErrNotFound) {
			return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
		}
		return fail(brokerapi.CodeNotFound, exitcode.Missing, backend.ErrNotFound)
	}
	// The record is written first: a delete that cannot be audited does not
	// happen, as for every other change.
	if err := a.emit(ctx, audit.ActionDelete, audit.OutcomeOK, res, map[string]any{"backend": "broker"}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	if err := a.p.store.Delete(ctx, req.Path); err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return fail(brokerapi.CodeNotFound, exitcode.Missing, err)
		}
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	return brokerapi.Response{OK: true}
}

func (a *admin) listSecrets(ctx context.Context) brokerapi.Response {
	entries, err := a.p.store.List(ctx, "")
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	out := make([]brokerapi.Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, brokerapi.Entry{Path: e.Path, Version: e.Version})
	}
	return brokerapi.Response{OK: true, Entries: out}
}

func (a *admin) changePolicy(ctx context.Context, res callerkind.Result, req brokerapi.Request, apply func() error) brokerapi.Response {
	if err := apply(); err != nil {
		_ = a.emit(ctx, audit.ActionPolicyChange, audit.OutcomeError, res, map[string]any{"change": string(req.Op), "reason": err.Error()})
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	if err := a.emit(ctx, audit.ActionPolicyChange, audit.OutcomeOK, res, map[string]any{"change": string(req.Op), "digest": req.Digest()}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	st := a.p.policy.Verify()
	return brokerapi.Response{OK: true, Policy: &st}
}

// migrateIn stores the secrets a user's adopt sends and answers with a keyed
// hash of each value read back from the store, so the client can check that
// every secret arrived intact without the daemon ever returning a value.
func (a *admin) migrateIn(ctx context.Context, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	macs := make(map[string]string, len(req.Items))
	for _, it := range req.Items {
		if _, err := a.p.store.Put(ctx, it.Path, it.Value); err != nil {
			return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
		}
	}
	for _, it := range req.Items {
		got, _, err := a.p.store.Get(ctx, it.Path)
		if err != nil {
			return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
		}
		macs[it.Path] = KeyedHash(req.Nonce, it.Path, got)
		clear(got)
	}
	extra := map[string]any{"count": len(req.Items), "old_audit_head": req.OldAuditHead}
	action := audit.ActionBrokerAdopt
	if req.Op == brokerapi.OpMigrateSources {
		action = audit.ActionMigrateImport
		extra = map[string]any{"count": len(req.Items), "request_digest": req.Digest()}
	}
	if err := a.emit(ctx, action, audit.OutcomeOK, res, extra); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true, MACs: macs}
}

func (a *admin) migrateOut(ctx context.Context, res callerkind.Result) brokerapi.Response {
	entries, err := a.p.store.List(ctx, "")
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	items := make([]brokerapi.Item, 0, len(entries))
	for _, e := range entries {
		v, _, err := a.p.store.Get(ctx, e.Path)
		if err != nil {
			return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
		}
		items = append(items, brokerapi.Item{Path: e.Path, Value: v})
	}
	if err := a.emit(ctx, audit.ActionBrokerExport, audit.OutcomeOK, res, map[string]any{"count": len(items)}); err != nil {
		return fail(brokerapi.CodeRefused, exitcode.SecurityBlock, err)
	}
	return brokerapi.Response{OK: true, Items: items}
}

func (a *admin) rotate(ctx context.Context, res callerkind.Result) brokerapi.Response {
	old := a.s.cfg.Keys.KeyID()
	if err := a.s.cfg.Keys.Rotate(a.s.rewrapAll); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	extra := map[string]any{"old_kek_type": "bmk:" + old, "new_kek_type": "bmk:" + a.s.cfg.Keys.KeyID()}
	_ = a.emit(ctx, audit.ActionKEKRotate, audit.OutcomeOK, res, extra)
	return a.status(ctx)
}

// KeyedHash is the hex HMAC-SHA256 of path and value under nonce. The client
// and the daemon compute it independently over a migrated secret.
func KeyedHash(nonce []byte, path string, value []byte) string {
	m := hmac.New(sha256.New, nonce)
	m.Write([]byte(path))
	m.Write([]byte{0})
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil))
}
