package main

import (
	"context"
	"crypto/ed25519"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/runapproval"
)

// newApprover wires approvals for runs that need one: the daemon opens a
// request that carries the exact plan, `keylatch approve <token>` decides it
// with a signature only the approver's passphrase can make, and the daemon
// starts the run only when the signed decision names this plan.
func newApprover(env llmcontext.Lookup, em audit.Emitter) control.Approver {
	a := &runapproval.Approver{
		Dir: paths.ApprovalsDir(env),
		PublicKey: func() (ed25519.PublicKey, error) {
			k, err := approval.LoadApproverKey(filepath.Join(paths.ConfigDir(env), "approver.json"))
			if err != nil {
				return nil, err
			}
			return k.Public()
		},
		Audit: em,
	}
	return func(ctx context.Context, req control.ApprovalRequest) (string, error) {
		return a.Approve(ctx, runapproval.Plan{
			Connection: req.Connection, Tier: string(req.Tier), Caller: string(req.Caller), Project: req.Project,
			Argv: req.Argv, Hosts: req.Hosts, TTL: req.TTL,
		}, req.Notify)
	}
}
