package explain

import (
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/policy"
)

// Tier statuses reported for a caller.
const (
	StatusAllowed     = "allowed"
	StatusApproval    = "approval"
	StatusDenied      = "denied"
	StatusUnavailable = "unavailable"
)

// PolicyInput is everything Effective needs. Resolve returns the facts for
// one connection name; Connection narrows the report to that name and Actor
// narrows it to one caller.
type PolicyInput struct {
	Policy     policy.Policy
	Manifest   manifest.Manifest
	Resolve    func(connection string) Connection
	Connection string
	Actor      string
}

// TierStatus is how one delivery tier fares for a caller and connection.
type TierStatus struct {
	Tier       string `json:"tier"`
	TierName   string `json:"tier_name"`
	Status     string `json:"status"`
	Runtime    string `json:"runtime"`
	Restricted bool   `json:"restricted"`
	Why        string `json:"why"`
}

// ConnectionPolicy is the effective policy for one connection.
type ConnectionPolicy struct {
	Connection string       `json:"connection"`
	Known      bool         `json:"known"`
	Hosts      []string     `json:"hosts"`
	Tiers      []TierStatus `json:"tiers"`
}

// CallerPolicy is the effective policy for one actor.
type CallerPolicy struct {
	Actor       string             `json:"actor"`
	CallerKind  string             `json:"caller_kind"`
	Connections []ConnectionPolicy `json:"connections"`
}

// PolicyReport is the effective policy per caller.
type PolicyReport struct {
	SchemaVersion int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	Policy        PolicyDetail   `json:"policy"`
	Callers       []CallerPolicy `json:"callers"`
	Notes         []string       `json:"notes"`
}

// PolicyDetail summarises the policy document.
type PolicyDetail struct {
	Mode        string `json:"mode"`
	DefaultDeny bool   `json:"default_deny"`
	RuleCount   int    `json:"rule_count"`
}

// Effective reports, per caller and connection, which delivery tiers the
// policy permits. Command and working-directory restrictions on a rule are not
// evaluated; tiers that depend on them are flagged restricted and should be
// confirmed with Run.
func Effective(in PolicyInput) PolicyReport {
	rep := PolicyReport{
		SchemaVersion: SchemaVersion,
		Kind:          "policy",
		Policy:        PolicyDetail{Mode: string(in.Policy.Mode), DefaultDeny: in.Policy.DefaultDeny, RuleCount: len(in.Policy.Rules)},
		Callers:       []CallerPolicy{},
		Notes:         []string{},
	}

	actors := []string{"human-shell", "llm-session"}
	conns := []string{}
	for _, r := range in.Policy.Rules {
		if literal(r.Actor) {
			actors = append(actors, r.Actor)
		}
		for _, c := range r.Connections {
			if literal(c) {
				conns = append(conns, c)
			}
		}
	}
	if in.Actor != "" {
		actors = []string{in.Actor}
	}
	if in.Connection != "" {
		conns = []string{in.Connection}
	}
	actors, conns = sortedUnique(actors), sortedUnique(conns)
	if len(conns) == 0 {
		rep.Notes = append(rep.Notes, "no rule names a connection explicitly; pass a connection name")
	}
	if len(in.Policy.Rules) > 0 {
		rep.Notes = append(rep.Notes, "rules limited by command or working directory are reported as restricted; use explain run for an exact answer")
	}

	relaxed, restricted := relaxCommandScope(in.Policy)
	for _, actor := range actors {
		kind := CallerKind(actor, false)
		cp := CallerPolicy{Actor: actor, CallerKind: kind, Connections: []ConnectionPolicy{}}
		llm := kind == CallerAgent
		for _, name := range conns {
			facts := in.Resolve(name)
			cn := ConnectionPolicy{Connection: name, Known: facts.Known, Hosts: sortedCopy(facts.Hosts), Tiers: []TierStatus{}}
			ein := Input{
				Policy:     relaxed,
				Manifest:   in.Manifest,
				Connection: facts,
				Request:    Request{Actor: actor, LLMSession: llm, Connection: name, Argv: []string{"-"}},
			}
			for _, ev := range evaluate(ein, kind) {
				cn.Tiers = append(cn.Tiers, tierStatus(ev, facts.Known, restricted))
			}
			cp.Connections = append(cp.Connections, cn)
		}
		rep.Callers = append(rep.Callers, cp)
	}
	return rep
}

func tierStatus(ev tierEval, known bool, restricted map[string]bool) TierStatus {
	ts := TierStatus{Tier: ev.info.ID, TierName: ev.info.Name, Why: ev.why}
	switch {
	case !known:
		ts.Status, ts.Why = StatusUnavailable, "connection is not known"
	case ev.eligible && (ev.approval || ev.info.ID == "D6"):
		ts.Status = StatusApproval
	case ev.eligible:
		ts.Status = StatusAllowed
	case ev.class == failPolicy || ev.class == failCaller:
		ts.Status = StatusDenied
	default:
		ts.Status = StatusUnavailable
	}
	if ev.eligible {
		ts.Runtime = ev.runtime
		ts.Why = "permitted"
		if ev.rule != nil {
			ts.Why = "permitted by policy rule " + ev.rule.ID
			ts.Restricted = restricted[ev.rule.ID]
		}
	}
	return ts
}

// relaxCommandScope returns a copy of p whose rules no longer carry command or
// working-directory patterns, plus the ids of the rules that had any.
func relaxCommandScope(p policy.Policy) (policy.Policy, map[string]bool) {
	restricted := map[string]bool{}
	rules := make([]policy.Rule, len(p.Rules))
	for i, r := range p.Rules {
		if len(r.Commands) > 0 || len(r.CWDs) > 0 {
			restricted[r.ID] = true
			r.Commands, r.CWDs = nil, nil
		}
		rules[i] = r
	}
	p.Rules = rules
	return p, restricted
}

func literal(s string) bool {
	return s != "" && !strings.ContainsAny(s, "*?[\\")
}

func sortedUnique(in []string) []string {
	out := dedupe(in)
	sort.Strings(out)
	if out == nil {
		return []string{}
	}
	return out
}
