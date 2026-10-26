package brokerd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/runapproval"
)

func (s *Server) approver(p *partition) control.Approver {
	a := &runapproval.Approver{
		Dir: paths.ApprovalsDir(p.env), Audit: s.cfg.Audit,
		PublicKey: func() (ed25519.PublicKey, error) {
			key, err := s.cfg.Keys.ApprovalSignerFor(uidString(p.uid))
			if err != nil {
				return nil, err
			}
			defer clear(key)
			return key.Public().(ed25519.PublicKey), nil
		},
	}
	return func(ctx context.Context, req control.ApprovalRequest) (string, error) {
		return a.Approve(ctx, runapproval.Plan{Connection: req.Connection, Tier: string(req.Tier), Caller: string(req.Caller), Project: req.Project, Argv: req.Argv, Hosts: req.Hosts, TTL: req.TTL}, req.Notify)
	}
}

func (a *admin) approvalPeer(ctx context.Context, peer control.Peer, res callerkind.Result) error {
	if peer.UID != a.p.uid || peer.PID <= 0 || peer.Start == "" {
		return ErrPeerGone
	}
	if peer.Verify != nil {
		if err := peer.Verify(); err != nil {
			return err
		}
	}
	return a.p.policy.Gate(ctx, res)
}

func approvalFailure(err error) brokerapi.Response {
	code := brokerapi.CodeRefused
	if errors.Is(err, approval.ErrNotFound) {
		code = brokerapi.CodeNotFound
	}
	return fail(code, exitcode.SecurityBlock, err)
}

func (a *admin) listApprovals(ctx context.Context, peer control.Peer, res callerkind.Result) brokerapi.Response {
	if err := a.approvalPeer(ctx, peer, res); err != nil {
		return approvalFailure(err)
	}
	requests, err := approval.List(ctx, paths.ApprovalsDir(a.p.env))
	if err != nil {
		return approvalFailure(err)
	}
	entries := make([]brokerapi.ApprovalEntry, 0, len(requests))
	for _, ar := range requests {
		entries = append(entries, brokerapi.ApprovalEntry{Token: ar.Token, Actor: approval.DisplaySafe(ar.Actor), Capability: approval.DisplaySafe(ar.Capability), Connection: approval.DisplaySafe(ar.Connection), Summary: approval.Summary(ar), RequestHash: approval.DisplaySafe(ar.RequestHash), Digest: approval.Digest(ar), Status: ar.Status, CreatedAt: ar.CreatedAt, ExpiresAt: ar.ExpiresAt})
	}
	return brokerapi.Response{OK: true, Approvals: entries}
}

func (a *admin) decideApproval(ctx context.Context, peer control.Peer, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	if err := req.Validate(); err != nil {
		return fail(brokerapi.CodeBadRequest, exitcode.UserError, err)
	}
	if res.Kind == callerkind.Agent {
		return presenceFailure(ErrAgentPresence)
	}
	if err := a.approvalPeer(ctx, peer, res); err != nil {
		return approvalFailure(err)
	}
	if !a.p.approvalMu.TryLock() {
		return presenceFailure(ErrPromptOpen)
	}
	defer a.p.approvalMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	d := req.Approval
	dir := paths.ApprovalsDir(a.p.env)
	ar, err := approval.Get(ctx, dir, d.Token)
	if err != nil {
		return approvalFailure(err)
	}
	if approval.Digest(ar) != d.Digest {
		return approvalFailure(approval.ErrChanged)
	}
	if ar.Status != approval.StatusPending {
		return approvalFailure(approval.ErrAlreadyActed)
	}
	if !ar.ExpiresAt.After(time.Now()) {
		return approvalFailure(approval.ErrExpired)
	}
	if ar.ExpiresAt.Sub(ar.CreatedAt) > approval.MaxTTL {
		return approvalFailure(approval.ErrTTLTooLong)
	}
	action, event := presence.ActionApprove, audit.ActionApprovalGranted
	if strings.HasPrefix(ar.Capability, "run:") {
		action = presence.ActionRunApprove
	}
	if d.Decision == "deny" {
		action, event = presence.ActionDeny, audit.ActionApprovalDenied
	}
	summary := approval.Summary(ar)
	if err := a.s.keyPresence(a.p.uid)(ctx, peer, action, summary); err != nil {
		return presenceFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return presenceFailure(err)
	}
	if err := a.approvalPeer(ctx, peer, res); err != nil {
		return approvalFailure(err)
	}
	current, err := approval.Get(ctx, dir, d.Token)
	if err != nil {
		return approvalFailure(err)
	}
	if approval.Digest(current) != d.Digest {
		return approvalFailure(approval.ErrChanged)
	}
	key, err := a.s.cfg.Keys.ApprovalSignerFor(uidString(a.p.uid))
	if err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	defer clear(key)
	proof := approval.Presence{Digest: presence.Digest(action, summary), Method: a.s.presence.Method.Name()}
	if err := a.emit(ctx, event, audit.OutcomeOK, res, map[string]any{"approval_id": d.Token, "connection": ar.Connection, "presence_digest": proof.Digest, "presence_method": proof.Method}); err != nil {
		return fail(brokerapi.CodeUnavailable, exitcode.OperationFailed, err)
	}
	if d.Decision == "approve" {
		err = approval.ApproveWithPresence(ctx, dir, d.Token, d.Digest, d.Reason, proof, key)
	} else {
		err = approval.DenyWithPresence(ctx, dir, d.Token, d.Digest, d.Reason, proof, key)
	}
	if err != nil {
		return approvalFailure(err)
	}
	return brokerapi.Response{OK: true}
}
