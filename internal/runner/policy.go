// Package runner extensions for policy gating.
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/grant"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/actor"
)

// ErrPolicyDeny is returned when policy.Check denies the request.
var ErrPolicyDeny = errors.New("policy: request denied")

// ErrApprovalRequired is returned when the policy decision requires approval.
var ErrApprovalRequired = errors.New("policy: approval required")

// PolicyOptions carries per-invocation policy check parameters.
type PolicyOptions struct {
	Actor       string // from --actor or inferred
	DryRun      bool
	Capability  string // default "inject"
	ApprovalJWT string
	Namespace   string
	Runtime     string
	PolicyPath  string // "" → default path
	GrantPath   string // "" → default path
}

// Receipt describes the outcome of a policy-gated run call.
// All hash fields are value-free.
type Receipt struct {
	Actor          string        `json:"actor"`
	Connection     string        `json:"connection"`
	Capability     string        `json:"capability"`
	Runtime        string        `json:"runtime"`
	CommandHash    string        `json:"command_hash"`
	CWDHash        string        `json:"cwd_hash"`
	PolicyDecision string        `json:"policy_decision"`
	AuditAccessor  string        `json:"audit_accessor"`
	ExitCode       int           `json:"exit_code,omitempty"`
	Duration       time.Duration `json:"duration"`
	Timestamp      time.Time     `json:"timestamp"`
}

// CheckPolicy evaluates a policy check for a given connection and command.
//
// Algorithm:
//  1. Load policy from opts.PolicyPath (or default via env).
//  2. Infer actor from env if opts.Actor == "".
//  3. Call policy.Check(req).
//  4. If deny: also call grant.Find — if a grant matches, return allow with
//     PolicyDecision="grant:<id>".
//  5. Return the decision.
//
// Returns ErrPolicyDeny if the final decision is deny.
// Returns ErrApprovalRequired if the decision requires approval.
func CheckPolicy(conn string, command []string, opts PolicyOptions) (policy.Decision, error) {
	env := llmcontext.DefaultLookup

	// Resolve paths.
	policyPath := opts.PolicyPath
	if policyPath == "" {
		policyPath = paths.Policy(env)
	}
	grantPath := opts.GrantPath
	if grantPath == "" {
		grantPath = paths.Grants(env)
	}

	// Load policy (if file doesn't exist, use a default-deny policy).
	p, err := policy.Load(policyPath)
	if err != nil {
		// Absent policy file → default-deny.
		if os.IsNotExist(err) || isPathNotFoundErr(err) {
			p = policy.Policy{
				SchemaVersion: 1,
				Mode:          policy.ModeEnforcing,
				DefaultDeny:   true,
			}
		} else {
			return policy.Decision{}, fmt.Errorf("runner: load policy: %w", err)
		}
	}

	// Infer actor.
	actorName := opts.Actor
	if actorName == "" {
		actorName = actor.Infer(env).Name
	}

	cap := opts.Capability
	if cap == "" {
		cap = "inject"
	}

	// Build request.
	cwd, _ := os.Getwd()
	req := policy.Request{
		Actor:       actorName,
		Connection:  conn,
		Capability:  cap,
		Command:     command,
		CWD:         cwd,
		LLMSession:  llmcontext.IsLLMSession(env),
		Runtime:     opts.Runtime,
		ApprovalJWT: opts.ApprovalJWT,
		Namespace:   opts.Namespace,
	}

	d := p.Check(req)

	// If denied, try grant.Find as an override.
	if !d.Allow {
		g, ok := grant.Find(context.Background(), grantPath, grant.FindRequest{
			Actor:      actorName,
			Connection: conn,
			Capability: cap,
			Command:    command,
			CWD:        cwd,
		})
		if ok && g != nil {
			d = policy.Decision{
				Allow:          true,
				MatchedGrantID: g.ID,
				Reason:         fmt.Sprintf("grant:%s", g.ID),
			}
		}
	}

	if !d.Allow {
		return d, ErrPolicyDeny
	}
	if d.ApprovalRequired {
		return d, ErrApprovalRequired
	}
	return d, nil
}

// hashValue returns a truncated SHA-256 hex of s (value-free).
//
//nolint:unused // planned: used by Receipt construction command/cwd hash fields
func hashValue(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

// isPathNotFoundErr checks if the error wraps a path-not-found condition.
func isPathNotFoundErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// CheckPolicyWithAudit is the audit-instrumented variant of CheckPolicy.
// It emits exactly one ActionPolicyCheck event per call.
func CheckPolicyWithAudit(
	ctx context.Context,
	logger *audit.Logger,
	conn string,
	command []string,
	opts PolicyOptions,
) (policy.Decision, error) {
	start := time.Now()
	d, err := CheckPolicy(conn, command, opts)

	outcome := audit.OutcomeOK
	if err == ErrPolicyDeny {
		outcome = audit.OutcomeDenied
	} else if err != nil {
		outcome = audit.OutcomeError
	}

	policyDecision := ""
	if d.Allow {
		policyDecision = "allow"
	} else {
		policyDecision = "deny"
	}
	if d.MatchedRule != nil {
		policyDecision += ":rule:" + d.MatchedRule.ID
	}
	if d.Reason != "" && strings.HasPrefix(d.Reason, "grant:") {
		policyDecision = d.Reason
	}

	if logger != nil {
		if logErr := logger.Log(ctx, audit.Event{
			Timestamp:   start,
			Action:      audit.ActionPolicyCheck,
			Outcome:     outcome,
			Path:        conn,
			RuntimeMode: opts.Runtime,
			Extra: map[string]any{
				// Only "policy_id" and "result" are in the SafeLogFields
				// allowlist for policy_check. Other keys will have
				// their values HMAC'd by the Redact filter.
				"result": policyDecision,
			},
		}); logErr != nil {
			// Audit write failures must not silently succeed — log to stderr
			// so the operator sees the failure even if the policy decision
			// itself is returned to the caller.
			slog.Error("runner audit log write failed", "error", logErr)
		}
	}

	return d, err
}
