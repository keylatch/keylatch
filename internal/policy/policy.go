// Package policy implements the keylatch policy engine.
// It provides a schema for policy rules, a decision engine, and persistence.
//
// Import constraints:
//   - This package MUST NOT import internal/grant to avoid circular imports.
//     Decision.MatchedGrantID carries only the grant ID string; callers look
//     up the full grant when needed.
package policy

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/policy/match"
	"github.com/keylatch/keylatch/internal/trust"
)

// SchemaVersion is the current supported schema version.
const SchemaVersion = 1

// Mode controls how the policy engine responds to denials.
type Mode string

const (
	ModeEnforcing  Mode = "enforcing"
	ModePermissive Mode = "permissive"
	ModeDryRun     Mode = "dry_run"
)

// OrgComposeHook is a Phase 12 forward-compat registration point.
// When non-nil, it is invoked first in Check; if it returns Allow=false, that
// decision is returned immediately without consulting local rules.
// Default nil.
var OrgComposeHook func(req Request) (Decision, bool)

// managementCaps are always allowed regardless of DefaultDeny.
var managementCaps = map[string]bool{
	"status": true,
	"list":   true,
}

// readClassCaps are denied in LLM sessions (S8-9).
var readClassCaps = map[string]bool{
	"read":   true,
	"export": true,
}

func isReadClassCap(cap string) bool {
	if readClassCaps[cap] {
		return true
	}
	if strings.HasSuffix(cap, ".reveal") || strings.HasSuffix(cap, ".dump") {
		return true
	}
	return false
}

// Policy holds the top-level policy document.
type Policy struct {
	SchemaVersion    int       `json:"schema_version"`
	Mode             Mode      `json:"mode"`
	Rules            []Rule    `json:"rules"`
	DefaultDeny      bool      `json:"default_deny"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	TeamModeBaseline bool      `json:"team_mode_baseline,omitempty"`
}

// RootRequirement describes the trust root constraint attached to a policy rule.
// It is used by the Phase 11 approval-root wiring (FIND2-003).
type RootRequirement struct {
	// Type is "any" (first matching from AnyOf) or "all" (all from AllOf required).
	Type string `json:"type,omitempty"`
	// AnyOf is a list of root spec IDs or RootType strings; first available wins.
	AnyOf []string `json:"any_of,omitempty"`
	// AllOf is a list of root spec IDs that ALL must be present (two-person).
	AllOf []string `json:"all_of,omitempty"`
	// MaxAgeSec is the maximum age (seconds) of a PresenceProof for this rule.
	MaxAgeSec int `json:"max_age_sec,omitempty"`
	// Bind controls challenge binding: "none", "command", "cwd", "full".
	Bind string `json:"bind,omitempty"`
	// TwoPerson requires two distinct presence proofs.
	TwoPerson bool `json:"two_person,omitempty"`
}

// Rule is a single policy rule entry.
type Rule struct {
	ID            string    `json:"id"`
	Actor         string    `json:"actor"`
	Connections   []string  `json:"connections"`
	Capabilities  []string  `json:"capabilities"`
	Commands      []string  `json:"commands,omitempty"`
	CWDs          []string  `json:"cwds,omitempty"`
	MaxTTLSeconds int       `json:"max_ttl_seconds,omitempty"`
	Approval      bool      `json:"approval,omitempty"`
	RateLimit     *RateSpec `json:"rate_limit,omitempty"`
	Note          string    `json:"note,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
	Project       string    `json:"project,omitempty"`

	// Phase 11: structured approval root requirement.
	// When non-nil, the matched decision requires a hardware-signed approval.
	ApprovalRootReq *RootRequirement `json:"approval_root_req,omitempty"`

	// Phase 11/12/13 forward-compat — round-trip unchanged.
	ApprovalRoot json.RawMessage `json:"approval_root,omitempty"`
	MemberID     string          `json:"member_id,omitempty"`
	Team         string          `json:"team,omitempty"`
	Masking      string          `json:"masking,omitempty"`
	Budget       json.RawMessage `json:"budget,omitempty"`
	TokenBroker  string          `json:"token_broker,omitempty"`

	// Runtime mode fields (launch-runtime-modes-architecture).
	Runtime        string            `json:"runtime,omitempty"`
	LLMSessions    map[string]string `json:"llm_sessions,omitempty"`
	SandboxProfile string            `json:"sandbox_profile,omitempty"`
	ProxyProfile   string            `json:"proxy_profile,omitempty"`

	// Legacy (backward compat — translate on load).
	AllowedRuntimes []string `json:"allowed_runtimes,omitempty"`
}

// RateSpec describes a rate-limiting window for a rule.
type RateSpec struct {
	MaxCalls int           `json:"max_calls"`
	Window   time.Duration `json:"window"`
}

// Request is the input to a policy check.
type Request struct {
	Actor       string
	Connection  string
	Capability  string
	Command     []string
	CWD         string
	LLMSession  bool
	Runtime     string
	ApprovalJWT string
	Namespace   string
	// PresenceProof is an optional presence proof for rules with ApprovalRootReq.
	// When set and the matched rule has a MaxAgeSec constraint, the age is enforced.
	PresenceProof *trust.PresenceProof
}

// Decision is the output of a policy check.
type Decision struct {
	Allow            bool
	MatchedRule      *Rule
	MatchedGrantID   string // grant.Grant.ID of the matching grant, if any
	Reason           string
	SafeFix          string
	ApprovalRequired bool
	ApprovalToken    string
	// Phase 11: when ApprovalRequired=true and the rule has an ApprovalRootReq,
	// ApprovalRootReq holds the resolved requirement for the caller to satisfy.
	ApprovalRootReq *RootRequirement
}

// Load reads the policy file at path, verifies it has mode 0o600, and
// unmarshals the JSON content.
func Load(path string) (Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: stat %q: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			return Policy{}, fmt.Errorf("policy: %q has unsafe permissions %04o (want 0600)", path, perm)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: read %q: %w", path, err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("policy: parse %q: %w", path, err)
	}
	// C-2/FIND2-023: validate runtime mode on every rule that specifies one.
	// Also reject rate_limit fields: the RateSpec is parsed but never enforced.
	// Accepting silently would create false security expectations.
	for i, rule := range p.Rules {
		if rule.Runtime != "" {
			if err := ValidateRuntimeMode(string(rule.Runtime)); err != nil {
				return Policy{}, fmt.Errorf("policy: rule %d has invalid runtime %q: %w", i, rule.Runtime, err)
			}
		}
		if rule.RateLimit != nil {
			return Policy{}, fmt.Errorf("policy: rule %d has rate_limit configured, but rate limiting is not yet enforced; remove rate_limit until a future release adds enforcement", i)
		}
	}
	return p, nil
}

// Save marshals p as JSON to path with mode 0o600 and updates UpdatedAt.
func Save(path string, p Policy) error {
	p.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("policy: write %q: %w", path, err)
	}
	// Enforce 0o600 explicitly (WriteFile may be affected by umask).
	// Windows NTFS does not enforce Unix permission bits; skip chmod there.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("policy: chmod %q: %w", path, err)
		}
	}
	return nil
}

// Check evaluates req against p and returns a Decision.
// See Phase 8 spec for the full algorithm.
func (p Policy) Check(req Request) Decision {
	// M-4: Preflight — reject removed runtime strings immediately.
	if req.Runtime != "" {
		if err := ValidateRuntimeMode(req.Runtime); err != nil {
			return Decision{Allow: false, Reason: err.Error()}
		}
	}

	// Step 1: OrgComposeHook.
	if OrgComposeHook != nil {
		if d, ok := OrgComposeHook(req); ok && !d.Allow {
			return d
		}
	}

	// Step 2: permissive + LLM session is an invariant violation.
	if req.LLMSession && p.Mode == ModePermissive {
		panic("policy invariant violation: permissive mode must not be used in LLM sessions; CLI must gate this")
	}

	// Management capabilities are implicitly allowed regardless of DefaultDeny.
	if managementCaps[req.Capability] {
		return Decision{Allow: true, Reason: "management capability implicitly allowed"}
	}

	// Step 3: categorical read-class LLM deny (S8-9).
	if req.LLMSession && isReadClassCap(req.Capability) {
		return Decision{
			Allow:   false,
			Reason:  "read-class capabilities are denied in LLM sessions",
			SafeFix: "run from a human terminal",
		}
	}

	// Steps 4–7: iterate rules top-down.
	for i := range p.Rules {
		rule := p.Rules[i]
		if !ruleMatches(rule, req) {
			continue
		}

		// Step 5: LLM session runtime policy.
		if req.LLMSession {
			if d, done := checkLLMSessionRuntime(rule, req); done {
				return d
			}
		}

		// Step 6: approval flag.
		if rule.Approval {
			// Phase 11: if a presence proof was supplied, validate its age against MaxAgeSec.
			if d, done := validatePresenceProof(req, rule); done {
				return d
			}
			d := Decision{
				Allow:            true,
				MatchedRule:      &p.Rules[i],
				ApprovalRequired: true,
				ApprovalToken:    randomToken(),
			}
			// Phase 11: propagate ApprovalRootReq if the rule has one.
			if rule.ApprovalRootReq != nil {
				d.ApprovalRootReq = rule.ApprovalRootReq
			}
			return d
		}
		// Phase 11: rule has ApprovalRootReq even without Approval=true.
		if rule.ApprovalRootReq != nil {
			// Validate presence proof age if supplied.
			if d, done := validatePresenceProof(req, rule); done {
				return d
			}
			return Decision{
				Allow:            true,
				MatchedRule:      &p.Rules[i],
				ApprovalRequired: true,
				ApprovalToken:    randomToken(),
				ApprovalRootReq:  rule.ApprovalRootReq,
			}
		}

		// Step 7: plain allow.
		return Decision{Allow: true, MatchedRule: &p.Rules[i]}
	}

	// Steps 8–9: no match.
	if p.DefaultDeny {
		return Decision{
			Allow:   false,
			Reason:  "no rule matches request",
			SafeFix: "run keylatch policy allow ... or run from a human shell",
		}
	}
	return Decision{Allow: true, Reason: "no rule, default-allow"}
}

// ruleMatches returns true when all fields of req satisfy the rule.
func ruleMatches(rule Rule, req Request) bool {
	// M-4: if rule.Runtime is a removed runtime string, it must never match.
	// Parse-time validation (C-2) should prevent reaching here, but guard defensively.
	if rule.Runtime != "" {
		if err := ValidateRuntimeMode(string(rule.Runtime)); err != nil {
			return false
		}
	}
	// Actor.
	if !match.MatchActor(rule.Actor, req.Actor) {
		return false
	}
	// Connection: any must match.
	if !anyMatch(rule.Connections, req.Connection, match.MatchConnection) {
		return false
	}
	// Capability: any must match.
	if !anyMatch(rule.Capabilities, req.Capability, match.MatchCapability) {
		return false
	}
	// Commands: empty = wildcard.
	if len(rule.Commands) > 0 {
		found := false
		for _, p := range rule.Commands {
			if match.MatchCommand(p, req.Command) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// CWDs: empty = wildcard.
	if len(rule.CWDs) > 0 {
		found := false
		for _, p := range rule.CWDs {
			if match.MatchCWD(p, req.CWD) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Runtime: empty = any.
	if rule.Runtime != "" && rule.Runtime != req.Runtime {
		return false
	}
	return true
}

func anyMatch(patterns []string, value string, fn func(string, string) bool) bool {
	for _, p := range patterns {
		if fn(p, value) {
			return true
		}
	}
	return false
}

// checkLLMSessionRuntime handles step 5 of Check for LLM sessions.
// Returns (decision, true) if the runtime policy terminates the check, or
// (zero, false) to continue.
func checkLLMSessionRuntime(rule Rule, req Request) (Decision, bool) {
	if rule.LLMSessions == nil {
		// No LLM session overrides configured.
		// direct_classic_sandboxed without explicit key → approval_required.
		if req.Runtime == "direct_classic_sandboxed" {
			return Decision{Allow: true, ApprovalRequired: true}, true
		}
		return Decision{}, false
	}
	switch rule.LLMSessions[req.Runtime] {
	case "deny":
		return Decision{
			Allow:   false,
			Reason:  fmt.Sprintf("runtime %s denied by rule.LLMSessions", req.Runtime),
			SafeFix: "use --runtime gateway_typed",
		}, true
	case "approval_required":
		return Decision{Allow: true, ApprovalRequired: true}, true
	case "allow":
		return Decision{}, false
	default:
		// Key absent.
		if req.Runtime == "direct_classic_sandboxed" {
			return Decision{Allow: true, ApprovalRequired: true}, true
		}
		return Decision{}, false
	}
}

// validatePresenceProof checks a PresenceProof against the rule's ApprovalRootReq.
// Returns a denial Decision when the proof is stale or the RootID binding mismatches.
// Returns (zero, false) when the proof is acceptable or no validation is required.
func validatePresenceProof(req Request, rule Rule) (Decision, bool) {
	if rule.ApprovalRootReq == nil {
		return Decision{}, false
	}
	if req.PresenceProof == nil {
		// No proof supplied — caller must supply one; approval remains required.
		return Decision{}, false
	}
	maxAge := rule.ApprovalRootReq.MaxAgeSec
	if maxAge > 0 {
		if err := trust.VerifyPresenceProofAge(*req.PresenceProof, maxAge); err != nil {
			return Decision{
				Allow:   false,
				Reason:  fmt.Sprintf("presence proof stale: %v", err),
				SafeFix: "re-approve with a fresh presence proof",
			}, true
		}
	}
	// Binding mismatch: if the rule requires TwoPerson and the proof's RootID is empty.
	if rule.ApprovalRootReq.TwoPerson && req.PresenceProof.RootID == "" {
		return Decision{
			Allow:   false,
			Reason:  "presence proof missing RootID for two-person binding",
			SafeFix: "re-approve using hardware root",
		}, true
	}
	return Decision{}, false
}

// randomToken returns 16 random bytes encoded as base32 (no padding).
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
