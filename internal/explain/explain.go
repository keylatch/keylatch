// Package explain answers "may this run, and how?" from a policy, a support
// manifest and facts about one connection. It is a pure function over its
// input: no file, environment, vault or network access, so it can run in the
// CLI, behind the daemon socket or inside a host guard unchanged. It never
// handles secret values; the only request data echoed back is a digest of argv.
package explain

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/registry"
)

// SchemaVersion is the version of the JSON documents produced by this package.
// It changes only when an existing field is removed or changes meaning.
const SchemaVersion = 1

// Decision values.
const (
	DecisionAllow    = "allow"
	DecisionApproval = "approval"
	DecisionDeny     = "deny"
)

// Child locations.
const (
	LocationCaller   = "caller"
	LocationKeylatch = "keylatch_sandbox"
	LocationHost     = "unsandboxed"
	LocationNone     = "none"
)

// Containment verdicts.
const (
	VerdictNoSecret    = "no_secret_in_child"
	VerdictContained   = "contained_by_keylatch"
	VerdictUncontained = "uncontained"
	VerdictNone        = "not_applicable"
)

// Approval modes.
const (
	ApprovalNone     = "none"
	ApprovalAsk      = "ask"
	ApprovalPresence = "presence"
)

// Caller kinds.
const (
	CallerHuman   = "human"
	CallerAgent   = "agent"
	CallerService = "service"
)

// Error codes carried in Report.Error.
const (
	ErrUnknownConnection = "unknown_connection"
	ErrInvalidRequest    = "invalid_request"
	ErrTierUnavailable   = "tier_unavailable"
)

const injectCapability = "inject"

type tierInfo struct {
	ID       string
	Name     string
	Runtimes []string
}

// tiers lists the delivery tiers strongest first. A tier with no runtimes has
// no implementation in the runtime catalog yet.
var tiers = []tierInfo{
	{ID: "D1", Name: "typed_action"},
	{ID: "D2", Name: "gateway_session", Runtimes: []string{string(policy.RuntimeGatewayTyped), string(policy.RuntimeGatewaySDK)}},
	{ID: "D3", Name: "placeholder_substitution", Runtimes: []string{string(policy.RuntimePlaceholder)}},
	{ID: "D4", Name: "protocol_adapter"},
	{ID: "D5", Name: "contained_raw", Runtimes: []string{string(policy.RuntimeContained)}},
	{ID: "D6", Name: "uncontained_raw", Runtimes: []string{string(policy.RuntimeDirectClassic)}},
}

var residualRisk = map[string]string{
	"D2": "The child holds a scoped, short-lived gateway session token, not the provider key. It can use every action the session allows until the token expires; a misused capability is bounded by scope and audit, not prevented.",
	"D3": "The child holds a placeholder that Keylatch swaps for the real value only toward the connection's own hosts. A misused capability on those hosts is bounded by scope and audit, not prevented.",
	"D5": "The real secret is in the environment of a process Keylatch contains. Code running there can encode the value in ways output masking does not detect, so agent-authored code needs approval.",
	"D6": "The real secret is in an uncontained process running as the user. Anything the child executes can read, store or send it; only a person at a terminal should choose this tier.",
}

const noBindingWhy = registry.NoBindingReason + ": the connection declares no hosts and slots for a placeholder to be substituted into"

const residualDenied = "No secret is delivered and no child process is started."

// Connection describes what is known about the connection being used.
type Connection struct {
	Known        bool     `json:"known"`
	Provider     string   `json:"provider,omitempty"`
	Hosts        []string `json:"hosts,omitempty"`
	Runtimes     []string `json:"runtimes,omitempty"`
	TypedActions bool     `json:"typed_actions,omitempty"`
	// Binding is the connection's substitution contract: the provider
	// template's, or the one a custom connection declares. Nil means none, and
	// the placeholder tier cannot serve the connection.
	Binding *BindingInfo `json:"binding,omitempty"`
}

// BindingInfo is the part of a binding a reader needs: where a secret may go.
type BindingInfo struct {
	Source string     `json:"source"`
	Hosts  []string   `json:"hosts"`
	Slots  []SlotInfo `json:"slots"`
}

// SlotInfo names one request position a secret field may be substituted into.
// Name holds the header or query name, or the user/password half of a Basic
// credential.
type SlotInfo struct {
	Field string   `json:"field"`
	In    string   `json:"in"`
	Name  string   `json:"name,omitempty"`
	Hosts []string `json:"hosts"`
}

// Binding sources.
const (
	BindingTemplate = "template"
	BindingCustom   = "custom"
)

// BindingOf describes a binding for a report. The hosts and slots are sorted
// so the document is deterministic.
func BindingOf(source string, b registry.Binding) *BindingInfo {
	info := &BindingInfo{Source: source, Hosts: sortedCopy(b.Hosts), Slots: []SlotInfo{}}
	for _, s := range b.Slots {
		name := s.Name
		if s.In == registry.SlotBasic {
			name = s.Part
		}
		info.Slots = append(info.Slots, SlotInfo{Field: s.Field, In: string(s.In), Name: name, Hosts: sortedCopy(s.Hosts)})
	}
	return info
}

// Request is the run being asked about.
type Request struct {
	Actor      string   `json:"actor"`
	LLMSession bool     `json:"llm_session,omitempty"`
	Connection string   `json:"connection"`
	Argv       []string `json:"argv"`
	CWD        string   `json:"cwd,omitempty"`
	// Tier optionally pins the delivery tier ("D1".."D6"); it never relaxes policy.
	Tier string `json:"tier,omitempty"`
}

// Input is everything Run needs.
type Input struct {
	Policy     policy.Policy
	Manifest   manifest.Manifest
	Connection Connection
	Request    Request
	// Document, when set, asks the connection policy documents about a caller
	// kind and runtime. It reports false when no document governs the
	// request, and the rules file then decides.
	Document DocumentFunc
}

// Verdict is the answer of a connection policy document.
type Verdict struct {
	Allow            bool
	ApprovalRequired bool
	Reason           string
	SafeFix          string
}

// DocumentFunc answers for one request, caller kind and runtime.
type DocumentFunc func(req Request, kind, runtime string) (Verdict, bool)

// RequestInfo echoes the request without argv content.
type RequestInfo struct {
	CallerKind string `json:"caller_kind"`
	Actor      string `json:"actor"`
	Connection string `json:"connection"`
	Executable string `json:"executable"`
	Argc       int    `json:"argc"`
	ArgvSHA256 string `json:"argv_sha256"`
	CWD        string `json:"cwd"`
}

// Containment states whether the secret reaches the child and who contains it.
type Containment struct {
	Verdict       string `json:"verdict"`
	SecretInChild bool   `json:"secret_in_child"`
}

// ApprovalInfo states whether a human must approve before the run proceeds.
type ApprovalInfo struct {
	Required bool   `json:"required"`
	Mode     string `json:"mode"`
}

// Scope is the grant that applies to the run.
type Scope struct {
	RuleID       *string  `json:"rule_id"`
	Capabilities []string `json:"capabilities"`
	Connections  []string `json:"connections"`
	TTLSeconds   *int     `json:"ttl_seconds"`
}

// Rejected names a tier that was not chosen and why.
type Rejected struct {
	Tier     string `json:"tier"`
	TierName string `json:"tier_name"`
	Why      string `json:"why"`
	// Code is a stable reason code when one applies, and Fix the command that
	// removes the cause.
	Code string `json:"code,omitempty"`
	Fix  string `json:"fix,omitempty"`
}

// PolicyInfo summarises the policy that was consulted.
type PolicyInfo struct {
	Mode        string `json:"mode"`
	DefaultDeny bool   `json:"default_deny"`
}

// ErrorInfo explains a request that could not be evaluated.
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Report is the answer to "may this run, and how?".
type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Kind          string       `json:"kind"`
	Decision      string       `json:"decision"`
	Tier          *string      `json:"tier"`
	TierName      *string      `json:"tier_name"`
	Runtime       *string      `json:"runtime"`
	ChildLocation string       `json:"child_location"`
	Containment   Containment  `json:"containment"`
	Approval      ApprovalInfo `json:"approval"`
	Request       RequestInfo  `json:"request"`
	Hosts         []string     `json:"hosts"`
	Binding       *BindingInfo `json:"binding,omitempty"`
	Scope         Scope        `json:"scope"`
	Reasons       []string     `json:"reasons"`
	Rejected      []Rejected   `json:"rejected_tiers"`
	ResidualRisk  string       `json:"residual_risk"`
	Policy        PolicyInfo   `json:"policy"`
	Error         *ErrorInfo   `json:"error,omitempty"`
}

// CallerKind classifies an actor name as human, agent or service.
func CallerKind(actor string, llmSession bool) string {
	if llmSession {
		return CallerAgent
	}
	if actor == "human-shell" {
		return CallerHuman
	}
	if actor == "llm-session" {
		return CallerAgent
	}
	for _, d := range harness.All() {
		if d.ID == actor {
			return CallerAgent
		}
	}
	return CallerService
}

type failClass int

const (
	failNone failClass = iota
	failRun
	failCaller
	failBuild
	failProvider
	failPolicy
)

type tierEval struct {
	info     tierInfo
	eligible bool
	class    failClass
	why      string
	fix      string
	runtime  string
	approval bool
	rootReq  bool
	rule     *policy.Rule
}

// Run explains a run request.
func Run(in Input) Report {
	req := in.Request
	kind := CallerKind(req.Actor, req.LLMSession)
	rep := Report{
		SchemaVersion: SchemaVersion,
		Kind:          "run",
		Decision:      DecisionDeny,
		ChildLocation: LocationNone,
		Containment:   Containment{Verdict: VerdictNone},
		Approval:      ApprovalInfo{Mode: ApprovalNone},
		Request:       requestInfo(req, kind),
		Hosts:         []string{},
		Scope:         Scope{Capabilities: []string{}, Connections: []string{}},
		Reasons:       []string{},
		Rejected:      []Rejected{},
		ResidualRisk:  residualDenied,
		Policy:        PolicyInfo{Mode: string(in.Policy.Mode), DefaultDeny: in.Policy.DefaultDeny},
	}

	if req.Connection == "" || len(req.Argv) == 0 {
		return fail(rep, ErrInvalidRequest, "a connection and a command are required")
	}
	if !in.Connection.Known {
		return fail(rep, ErrUnknownConnection, "no connection named "+req.Connection+"; run: keylatch connect "+providerOf(req.Connection))
	}
	if req.Tier != "" && lookupTier(req.Tier) == nil {
		return fail(rep, ErrInvalidRequest, "tier must be one of D1..D6")
	}

	evals := evaluate(in, kind)
	chosen := choose(evals, req.Tier)
	if chosen == nil {
		rep.Rejected = rejectedExcept(evals, "", req.Tier != "")
		rep.Reasons = denialReasons(evals, req.Tier)
		if req.Tier != "" {
			rep.Error = &ErrorInfo{Code: ErrTierUnavailable, Message: "requested tier " + req.Tier + " cannot be used for this run"}
		}
		return rep
	}

	rep.Rejected = rejectedExcept(evals, chosen.info.ID, req.Tier != "")
	rep.Tier = ptr(chosen.info.ID)
	rep.TierName = ptr(chosen.info.Name)
	rep.Runtime = ptr(chosen.runtime)
	rep.ResidualRisk = residualRisk[chosen.info.ID]
	rep.Hosts = sortedCopy(in.Connection.Hosts)
	rep.Binding = in.Connection.Binding
	rep.ChildLocation, rep.Containment = placement(chosen.info.ID)
	rep.Scope = scopeOf(chosen.rule)

	needsApproval := chosen.approval || chosen.info.ID == "D6"
	if needsApproval {
		rep.Decision = DecisionApproval
		rep.Approval = ApprovalInfo{Required: true, Mode: ApprovalAsk}
		if chosen.rootReq || chosen.info.ID == "D6" {
			rep.Approval.Mode = ApprovalPresence
		}
	} else {
		rep.Decision = DecisionAllow
	}
	rep.Reasons = allowReasons(chosen, rep.Approval, req.Tier)
	return rep
}

func fail(rep Report, code, msg string) Report {
	rep.Error = &ErrorInfo{Code: code, Message: msg}
	rep.Reasons = []string{msg}
	return rep
}

func requestInfo(req Request, kind string) RequestInfo {
	exe := ""
	if len(req.Argv) > 0 {
		exe = filepath.Base(req.Argv[0])
	}
	sum := sha256.Sum256([]byte(strings.Join(req.Argv, "\x00")))
	return RequestInfo{
		CallerKind: kind,
		Actor:      req.Actor,
		Connection: req.Connection,
		Executable: exe,
		Argc:       len(req.Argv),
		ArgvSHA256: hex.EncodeToString(sum[:]),
		CWD:        req.CWD,
	}
}

func placement(tier string) (string, Containment) {
	switch tier {
	case "D5":
		return LocationKeylatch, Containment{Verdict: VerdictContained, SecretInChild: true}
	case "D6":
		return LocationHost, Containment{Verdict: VerdictUncontained, SecretInChild: true}
	default:
		return LocationCaller, Containment{Verdict: VerdictNoSecret}
	}
}

func scopeOf(rule *policy.Rule) Scope {
	s := Scope{Capabilities: []string{}, Connections: []string{}}
	if rule == nil {
		return s
	}
	s.RuleID = ptr(rule.ID)
	s.Capabilities = append(s.Capabilities, rule.Capabilities...)
	s.Connections = append(s.Connections, rule.Connections...)
	if rule.MaxTTLSeconds > 0 {
		s.TTLSeconds = ptr(rule.MaxTTLSeconds)
	}
	return s
}

func evaluate(in Input, kind string) []tierEval {
	evals := make([]tierEval, 0, len(tiers))
	for _, t := range tiers {
		evals = append(evals, evalTier(in, kind, t))
	}
	return evals
}

func evalTier(in Input, kind string, t tierInfo) tierEval {
	ev := tierEval{info: t}
	reject := func(c failClass, why, fix string) tierEval {
		ev.class, ev.why, ev.fix = c, why, fix
		return ev
	}
	switch {
	case t.ID == "D1":
		return reject(failRun, "typed actions run without a child process; use keylatch call", "")
	case len(t.Runtimes) == 0:
		return reject(failBuild, "no delivery implementation exists in this build", "")
	case t.ID == "D6" && kind != CallerHuman:
		return reject(failCaller, "uncontained raw delivery is human-only", "")
	}

	var whys, fixes []string
	class := failNone
	for _, rt := range t.Runtimes {
		c, why, fix, res := evalRuntime(in, kind, rt)
		if c == failNone {
			ev.eligible, ev.runtime = true, rt
			ev.approval, ev.rootReq, ev.rule = res.approval, res.rootReq, res.rule
			return ev
		}
		if class == failNone || c > class {
			class = c
		}
		whys = append(whys, why)
		if fix != "" {
			fixes = append(fixes, fix)
		}
	}
	return reject(class, strings.Join(dedupe(whys), "; "), strings.Join(dedupe(fixes), "; "))
}

type runtimeResult struct {
	approval bool
	rootReq  bool
	rule     *policy.Rule
}

func evalRuntime(in Input, kind, rt string) (failClass, string, string, runtimeResult) {
	var res runtimeResult
	if !in.Manifest.Enabled(rt) {
		why := "runtime " + rt + " is not supported in this build"
		if e, ok := in.Manifest.Lookup(rt); ok {
			why += " (" + e.Note + ")"
		}
		return failBuild, why, "", res
	}
	switch rt {
	case string(policy.RuntimePlaceholder):
		if in.Connection.Binding == nil {
			return failProvider, noBindingWhy, registry.NoBindingFix(providerOf(in.Request.Connection)), res
		}
	case string(policy.RuntimeContained):
		// The sandbox needs no provider support: any stored secret can be handed to it.
	default:
		if !contains(in.Connection.Runtimes, rt) {
			return failProvider, "provider does not support runtime " + rt, "", res
		}
	}
	if in.Request.LLMSession && in.Policy.Mode == policy.ModePermissive {
		return failPolicy, "permissive policy mode cannot be used in an agent session", "set the policy mode to enforcing", res
	}
	if in.Document != nil {
		if v, ok := in.Document(in.Request, kind, rt); ok {
			if !v.Allow {
				return failPolicy, nonEmpty(v.Reason, "denied by connection policy"), v.SafeFix, res
			}
			res.approval = v.ApprovalRequired
			return failNone, "", "", res
		}
	}
	d := in.Policy.Check(policy.Request{
		Actor:      in.Request.Actor,
		Connection: in.Request.Connection,
		Capability: injectCapability,
		Command:    in.Request.Argv,
		CWD:        in.Request.CWD,
		LLMSession: in.Request.LLMSession,
		Runtime:    rt,
	})
	if !d.Allow {
		return failPolicy, nonEmpty(d.Reason, "denied by policy"), d.SafeFix, res
	}
	res.approval = d.ApprovalRequired
	res.rootReq = d.ApprovalRootReq != nil
	res.rule = d.MatchedRule
	return failNone, "", "", res
}

func choose(evals []tierEval, requested string) *tierEval {
	for i := range evals {
		if !evals[i].eligible {
			continue
		}
		if requested == "" || requested == evals[i].info.ID {
			return &evals[i]
		}
	}
	return nil
}

func rejectedExcept(evals []tierEval, chosen string, requested bool) []Rejected {
	out := []Rejected{}
	for _, ev := range evals {
		if ev.info.ID == chosen {
			continue
		}
		why := ev.why
		if ev.eligible {
			why = "eligible but a stronger tier was selected"
			if requested {
				why = "eligible but a different tier was requested"
			}
		}
		r := Rejected{Tier: ev.info.ID, TierName: ev.info.Name, Why: why}
		if !ev.eligible && strings.HasPrefix(ev.why, registry.NoBindingReason) {
			r.Code, r.Fix = registry.NoBindingReason, ev.fix
		}
		out = append(out, r)
	}
	return out
}

func allowReasons(ch *tierEval, appr ApprovalInfo, requested string) []string {
	var out []string
	if ch.rule != nil {
		out = append(out, "allowed by policy rule "+ch.rule.ID)
	} else {
		out = append(out, "no rule matched; the policy allows by default")
	}
	how := "strongest eligible tier"
	if requested != "" {
		how = "requested tier"
	}
	out = append(out, how+" "+ch.info.ID+" ("+ch.info.Name+") via runtime "+ch.runtime)
	if appr.Required {
		switch {
		case ch.info.ID == "D6":
			out = append(out, "uncontained raw delivery needs approval with presence")
		case appr.Mode == ApprovalPresence:
			out = append(out, "the matching rule requires approval with presence")
		default:
			out = append(out, "the matching rule requires approval")
		}
	}
	return out
}

func denialReasons(evals []tierEval, requested string) []string {
	var out []string
	for _, ev := range evals {
		if strings.HasPrefix(ev.why, registry.NoBindingReason) {
			out = append(out, ev.info.ID+": "+ev.why, "fix: "+ev.fix)
		}
		if ev.class == failPolicy {
			out = append(out, "policy: "+ev.why)
			if ev.fix != "" {
				out = append(out, "fix: "+ev.fix)
			}
		}
	}
	out = dedupe(out)
	if requested != "" {
		out = append(out, "tier "+requested+" is not eligible for this run")
	}
	return append(out, "no delivery tier is eligible for this run")
}

func lookupTier(id string) *tierInfo {
	for i := range tiers {
		if tiers[i].ID == id {
			return &tiers[i]
		}
	}
	return nil
}

func providerOf(connection string) string {
	if i := strings.IndexByte(connection, ':'); i > 0 {
		return connection[:i]
	}
	return connection
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func ptr[T any](v T) *T { return &v }
