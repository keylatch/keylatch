// Package enforce is the one place that decides whether a request may use a
// connection. run, call and the gateway all ask Decide; none of them
// re-implements a check, so the same request gets the same answer everywhere.
//
// The answer is deny unless a policy says otherwise:
//
//  1. A connection policy document for the connection decides on its own.
//  2. Otherwise the rules file (policy.json) decides. A rules file without
//     default_deny denies what no rule allows.
//  3. Otherwise the fallback document ("*") decides.
//  4. With no policy at all the request is denied.
//
// A denial can be overridden only by a grant that was issued with a human
// presence proof.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/grant"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/actor"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
)

// DefaultAction is the capability of running a command with a credential.
const DefaultAction = "inject"

// Request is one use of a connection.
type Request struct {
	Connection string
	// Action is the capability asked for; empty means DefaultAction.
	Action string
	// Runtime is the runtime mode; empty for requests that have none.
	Runtime string
	// Caller is who is asking. Empty counts as host.
	Caller callerkind.Kind
	// Actor is the rule-file actor; empty infers it from the environment.
	Actor string
	// Command and CWD describe a run; empty for gateway requests.
	Command []string
	CWD     string
	// Unit is the systemd unit of a service caller, when known.
	Unit        string
	ApprovalJWT string
	Namespace   string
	// Tier is the delivery tier asked for (D1 to D6); empty for requests that
	// do not pick one.
	Tier string
}

// Decision is the verdict and where it came from.
type Decision struct {
	Allow bool
	// ApprovalRequired is set on an allow that still needs an out-of-band
	// approval; callers that cannot collect one must treat it as a deny.
	ApprovalRequired bool
	Reason           string
	SafeFix          string
	// Source is "connection-policy", "rules", "fallback-policy", "grant" or "none".
	Source  string
	RuleID  string
	GrantID string
	// MaxTTL caps the lifetime of anything issued for the request; zero is no cap.
	MaxTTL time.Duration
	// Approval is what the policy says about approving the request: "auto",
	// "ask", "auto_if_contained" or "presence"; empty when it says nothing.
	Approval string
	// EgressAllow lists the non-secret destinations contained children may
	// reach, and FSRead and FSWrite the paths they may read and write; empty
	// means the policy sets none.
	EgressAllow []string
	FSRead      []string
	FSWrite     []string
}

// Enforcer reads the policy a request is decided against.
type Enforcer struct {
	PolicyPath string
	PolicyDir  string
	GrantPath  string
	// Rules, when set, is the rules policy to use instead of reading
	// PolicyPath. A long-running server loads and validates it once.
	Rules *policy.Policy

	allowAll bool
}

// New returns an Enforcer for the policy locations of env.
func New(env llmcontext.Lookup) *Enforcer {
	return &Enforcer{
		PolicyPath: paths.Policy(env),
		PolicyDir:  paths.PolicyDir(env),
		GrantPath:  paths.Grants(env),
	}
}

var (
	defaultMu sync.RWMutex
	defaultE  *Enforcer
)

// Default is the Enforcer for the process's own policy locations.
func Default() *Enforcer {
	defaultMu.RLock()
	e := defaultE
	defaultMu.RUnlock()
	if e != nil {
		return e
	}
	return New(llmcontext.DefaultLookup)
}

// SetDefault replaces Default and returns a function that restores it. It
// panics outside tests.
func SetDefault(e *Enforcer) (restore func()) {
	if !testing.Testing() {
		panic("enforce: SetDefault is only available in tests")
	}
	defaultMu.Lock()
	prev := defaultE
	defaultE = e
	defaultMu.Unlock()
	return func() {
		defaultMu.Lock()
		defaultE = prev
		defaultMu.Unlock()
	}
}

// AllowAll returns an Enforcer that allows every request, for tests that are
// not about policy. It panics outside tests.
func AllowAll() *Enforcer {
	if !testing.Testing() {
		panic("enforce: AllowAll is only available in tests")
	}
	return &Enforcer{allowAll: true}
}

// Decide asks the process's default Enforcer.
func Decide(ctx context.Context, req Request) Decision {
	return Default().Decide(ctx, req)
}

// NoPolicyReason is the reason given when nothing governs a connection.
func NoPolicyReason(connection string) string {
	return fmt.Sprintf("no policy for %s: run `keylatch policy init`", connection)
}

// Decide decides req.
func (e *Enforcer) Decide(ctx context.Context, req Request) Decision {
	if e.allowAll {
		return Decision{Allow: true, Source: "none"}
	}
	if req.Action == "" {
		req.Action = DefaultAction
	}
	if req.Caller == "" {
		req.Caller = callerkind.Host
	}
	d := e.decide(req)
	if d.Allow {
		return d
	}
	if g, ok := e.findGrant(ctx, req); ok {
		return Decision{Allow: true, Source: "grant", GrantID: g.ID, Reason: "grant:" + g.ID}
	}
	return d
}

func (e *Enforcer) decide(req Request) Decision {
	store := connpolicy.Store{Dir: e.PolicyDir}
	own, err := store.Load(req.Connection)
	if err != nil {
		return unreadable(req.Connection, err)
	}
	if own != nil {
		return fromDocument(*own, req, "connection-policy")
	}

	var (
		rules     policy.Policy
		haveRules bool
	)
	if e.Rules != nil {
		rules, haveRules = *e.Rules, true
	} else if rules, haveRules, err = loadRules(e.PolicyPath); err != nil {
		return unreadable(req.Connection, err)
	}
	var ruleDeny Decision
	if haveRules {
		d := checkRules(rules, req)
		if d.Allow {
			return d
		}
		ruleDeny = d
	}

	fallback, err := store.Load(connpolicy.Fallback)
	if err != nil {
		return unreadable(req.Connection, err)
	}
	if fallback != nil {
		return fromDocument(*fallback, req, "fallback-policy")
	}
	if haveRules {
		return ruleDeny
	}
	return Decision{Reason: NoPolicyReason(req.Connection), SafeFix: "run `keylatch policy init`", Source: "none"}
}

func unreadable(connection string, err error) Decision {
	return Decision{
		Reason:  fmt.Sprintf("the policy for %s cannot be read, so it is denied: %v", connection, err),
		SafeFix: "fix or re-import the policy with `keylatch policy import`",
		Source:  "none",
	}
}

func fromDocument(doc connpolicy.Document, req Request, source string) Decision {
	cd := doc.Decide(connpolicy.Request{
		Action:  req.Action,
		Runtime: req.Runtime,
		Caller:  req.Caller,
		Command: req.Command,
		Unit:    req.Unit,
	})
	d := Decision{Allow: cd.Allow, Reason: cd.Reason, Source: source, MaxTTL: cd.MaxTTL}
	if !d.Allow {
		d.SafeFix = "change the connection's policy with `keylatch policy import`"
	}
	return d
}

func loadRules(path string) (policy.Policy, bool, error) {
	p, err := policy.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Policy{}, false, nil
	}
	if err != nil {
		return policy.Policy{}, false, err
	}
	return p, true, nil
}

func checkRules(p policy.Policy, req Request) (d Decision) {
	name := req.Actor
	if name == "" {
		name = actor.Infer(llmcontext.DefaultLookup).Name
	}
	// policy.Check panics for a permissive policy in an agent session; an
	// invariant violation is a deny.
	defer func() {
		if r := recover(); r != nil {
			d = Decision{Reason: fmt.Sprintf("policy invariant violation: %v", r), SafeFix: "use enforcing mode", Source: "rules"}
		}
	}()
	pd := p.Check(policy.Request{
		Actor:       name,
		Connection:  req.Connection,
		Capability:  req.Action,
		Command:     req.Command,
		CWD:         req.CWD,
		LLMSession:  req.Caller == callerkind.Agent,
		Runtime:     req.Runtime,
		ApprovalJWT: req.ApprovalJWT,
		Namespace:   req.Namespace,
	})
	d = Decision{Allow: pd.Allow, ApprovalRequired: pd.ApprovalRequired, Reason: pd.Reason, SafeFix: pd.SafeFix, Source: "rules"}
	if pd.MatchedRule != nil {
		d.RuleID = pd.MatchedRule.ID
	}
	return d
}

func (e *Enforcer) findGrant(ctx context.Context, req Request) (*grant.Grant, bool) {
	if e.GrantPath == "" {
		return nil, false
	}
	name := req.Actor
	if name == "" {
		name = actor.Infer(llmcontext.DefaultLookup).Name
	}
	return grant.Find(ctx, e.GrantPath, grant.FindRequest{
		Actor:           name,
		Connection:      req.Connection,
		Capability:      req.Action,
		Command:         req.Command,
		CWD:             req.CWD,
		RequirePresence: true,
	})
}
