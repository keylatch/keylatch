// Package connpolicy is the per-connection policy document: which caller
// kinds may use a connection, under which runtimes, tiers and executables, to
// which hosts, with which filesystem and egress, and with what approval. It
// validates documents against schemas/connection-policy.schema.json, stores
// them as one file per connection and decides requests. internal/policy/enforce
// is the only caller that turns a decision into an allow or a deny.
package connpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/schemas"
)

// SchemaVersion is the document schema version.
const SchemaVersion = 2

// Fallback is the connection name of the document that governs connections
// without one of their own.
const Fallback = "*"

var connectionRe = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._-]{0,127})$`)

// Kinds lists the caller kinds a document can mention, in a stable order.
var Kinds = []callerkind.Kind{callerkind.Agent, callerkind.Host, callerkind.Service, callerkind.Human}

// Document is one connection's policy.
type Document struct {
	SchemaVersion int      `json:"schema_version"`
	Description   string   `json:"description,omitempty"`
	Connection    string   `json:"connection"`
	Default       string   `json:"default,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	MaxTTL        string   `json:"max_ttl,omitempty"`
	// Hosts narrows the hosts the connection's credential may reach: only
	// hosts both the provider template and this list name stay.
	Hosts []string `json:"hosts,omitempty"`
	// Egress lists the non-secret destinations a contained run may reach.
	Egress *Egress `json:"egress,omitempty"`
	// FS bounds what a contained run may read and write.
	FS *FS `json:"fs,omitempty"`
	// Commands pin argv patterns to tiers and approvals.
	Commands []CommandRule `json:"commands,omitempty"`
	// Host records the limits of the agent's own sandbox, imported with
	// `policy import --from`; they only narrow the document.
	Host    *HostBounds                    `json:"host,omitempty"`
	Callers map[callerkind.Kind]CallerRule `json:"callers,omitempty"`
}

// Egress is the non-secret network policy of contained runs.
type Egress struct {
	// Allow lists host[:port] patterns; empty means none beyond the
	// connection's own hosts.
	Allow []string `json:"allow,omitempty" yaml:"allow"`
	// DenyPrivateRanges is always true: private, link-local and metadata
	// ranges are never reachable. It is a field so a document says so.
	DenyPrivateRanges *bool `json:"deny_private_ranges,omitempty" yaml:"deny_private_ranges"`
}

// FS bounds the filesystem of contained runs. Paths are absolute, start with
// "~/" or start with a ${variable}: project, toolchain_caches,
// keylatch_state, browser_profiles or harness_config.
type FS struct {
	Read  []string `json:"read,omitempty" yaml:"read"`
	Write []string `json:"write,omitempty" yaml:"write"`
	Deny  []string `json:"deny,omitempty" yaml:"deny"`
}

// CallerRule says whether a caller kind may use the connection. The zero value
// denies.
type CallerRule struct {
	Allow    bool
	Runtimes []string
	Exe      []string
	Units    []string
	// Tiers lists the delivery tiers the kind may use; empty selects
	// DefaultTiers.
	Tiers []string
	// Approval is one of the approval modes; empty selects DefaultApproval.
	Approval string
	// TTL caps the lifetime of a session or child for this kind.
	TTL string
	// MaxRequests caps the requests a placeholder session may serve.
	MaxRequests int
}

type callerRuleObject struct {
	Allow       bool     `json:"allow"`
	Runtimes    []string `json:"runtimes,omitempty"`
	Exe         []string `json:"exe,omitempty"`
	Units       []string `json:"units,omitempty"`
	Tiers       []string `json:"tiers,omitempty"`
	Approval    string   `json:"approval,omitempty"`
	TTL         string   `json:"ttl,omitempty"`
	MaxRequests int      `json:"max_requests,omitempty"`
}

func (r CallerRule) isDeny() bool {
	return !r.Allow && len(r.Runtimes) == 0 && len(r.Exe) == 0 && len(r.Units) == 0 && len(r.Tiers) == 0 &&
		r.Approval == "" && r.TTL == "" && r.MaxRequests == 0
}

// MarshalJSON writes a denying rule as the string "deny".
func (r CallerRule) MarshalJSON() ([]byte, error) {
	if r.isDeny() {
		return []byte(`"deny"`), nil
	}
	return json.Marshal(callerRuleObject(r))
}

// UnmarshalJSON accepts "deny" or an object and rejects unknown keys.
func (r *CallerRule) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "deny" {
			return fmt.Errorf("caller rule %q: the only string form is \"deny\"", s)
		}
		*r = CallerRule{}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var o callerRuleObject
	if err := dec.Decode(&o); err != nil {
		return fmt.Errorf("caller rule: %w", err)
	}
	*r = CallerRule(o)
	return nil
}

// Request is what a document decides.
type Request struct {
	Action  string
	Runtime string
	Caller  callerkind.Kind
	// Command is the argv of a run; empty for requests that start no process.
	Command []string
	// Unit is the systemd unit of a service caller, when known.
	Unit string
	// Tier is the delivery tier asked for; empty for requests that choose none.
	Tier string
	// Exe is the real path of the executable Command[0] resolves to.
	Exe string
	// Pins verifies a pinned executable; nil selects VerifyPinned.
	Pins func(path, sha256 string) error
}

// Decision is a document's verdict.
type Decision struct {
	Allow  bool
	Reason string
	MaxTTL time.Duration
	// Tiers are the tiers the caller kind may use here.
	Tiers []string
	// Approval is what the request needs first: "auto", "ask" or "presence".
	// It is empty for a request that asks for no tier.
	Approval string
	// Pinned is set when a command rule with a verified executable hash matched.
	Pinned      bool
	MaxRequests int
	// Hosts is the document's own host list, to intersect with the template's.
	// Egress is the effective non-secret destinations, FSRead and FSWrite
	// the document's paths with variables unexpanded, FSDeny the union of the
	// document's and the host's denies.
	Hosts   []string
	Egress  []string
	FSRead  []string
	FSWrite []string
	FSDeny  []string
	// HostWrite lists the paths the host sandbox lets a run write; it applies
	// only when HostWriteRestricted is set.
	HostWrite           []string
	HostWriteRestricted bool
}

// Decide applies the document to req. Everything the document does not allow
// is denied.
func (d Document) Decide(req Request) Decision {
	deny := func(format string, args ...any) Decision {
		return Decision{Reason: fmt.Sprintf(format, args...)}
	}
	rule, ok := d.Callers[req.Caller]
	if !ok {
		return deny("connection %q has no callers.%s entry, so %s callers are denied", d.Connection, req.Caller, req.Caller)
	}
	if !rule.Allow {
		return deny("connection %q denies %s callers", d.Connection, req.Caller)
	}
	if len(rule.Runtimes) > 0 && !slices.Contains(rule.Runtimes, req.Runtime) {
		if req.Runtime == "" {
			return deny("connection %q allows %s callers only under %s, and this request has no runtime", d.Connection, req.Caller, strings.Join(rule.Runtimes, ", "))
		}
		return deny("connection %q allows %s callers only under %s, not %s", d.Connection, req.Caller, strings.Join(rule.Runtimes, ", "), req.Runtime)
	}
	if len(rule.Exe) > 0 && len(req.Command) > 0 && !exeAllowed(rule.Exe, req.Command[0]) {
		return deny("connection %q does not allow %s callers to start %s", d.Connection, req.Caller, filepath.Base(req.Command[0]))
	}
	if req.Caller == callerkind.Service && len(rule.Units) > 0 && !slices.Contains(rule.Units, req.Unit) {
		return deny("connection %q allows service callers only in %s", d.Connection, strings.Join(rule.Units, ", "))
	}
	if len(d.Capabilities) > 0 && !capabilityAllowed(d.Capabilities, req.Action) {
		return deny("connection %q does not allow the %q capability", d.Connection, req.Action)
	}

	tiers := rule.Tiers
	if len(tiers) == 0 {
		tiers = DefaultTiers(req.Caller)
	}
	out := Decision{Allow: true, Tiers: slices.Clone(tiers), MaxRequests: rule.MaxRequests, Hosts: slices.Clone(d.Hosts)}
	out.MaxTTL, _ = d.TTL()
	if t, _ := ttl(rule.TTL); t > 0 && (out.MaxTTL == 0 || t < out.MaxTTL) {
		out.MaxTTL = t
	}
	out.Egress = d.EffectiveEgress()
	out.FSDeny = d.EffectiveDeny()
	if d.FS != nil {
		out.FSRead, out.FSWrite = slices.Clone(d.FS.Read), slices.Clone(d.FS.Write)
	}
	if d.Host != nil {
		out.HostWrite, out.HostWriteRestricted = slices.Clone(d.Host.FSWrite), d.Host.WriteRestricted
	}

	mode := rule.Approval
	if mode == "" {
		mode = DefaultApproval(req.Caller)
	}
	var pinnedDenied string
	if match := d.matchCommand(req); match != nil {
		// A matched command rule narrows the tiers and may set the approval.
		if len(match.Tiers) > 0 {
			out.Tiers = intersectStrings(out.Tiers, match.Tiers)
		}
		if match.Approval != "" {
			mode = match.Approval
		}
		if match.ExeSHA256 != "" {
			verify := req.Pins
			if verify == nil {
				verify = VerifyPinned
			}
			if err := verify(req.Exe, match.ExeSHA256); err != nil {
				pinnedDenied = err.Error()
			} else {
				out.Pinned = true
			}
		}
	}
	if req.Tier != "" {
		if !slices.Contains(out.Tiers, req.Tier) {
			return deny("connection %q does not allow %s callers tier %s (allowed: %s)", d.Connection, req.Caller, req.Tier, strings.Join(out.Tiers, ", "))
		}
		if pinnedDenied != "" && req.Tier == D5 {
			// The rule asked for a pinned executable and this is not it: the
			// command does not run at all rather than falling back to an
			// unpinned run.
			return deny("connection %q pins this command to an executable that no longer matches: %s", d.Connection, pinnedDenied)
		}
		out.Approval = ResolveApproval(mode, req.Tier, out.Pinned)
	}
	return out
}

// matchCommand returns the first command rule req's argv matches.
func (d Document) matchCommand(req Request) *CommandRule {
	for i := range d.Commands {
		if MatchArgv(d.Commands[i].Match, req.Command, req.Exe) {
			return &d.Commands[i]
		}
	}
	return nil
}

func intersectStrings(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// TTL returns max_ttl, or zero when unset.
func (d Document) TTL() (time.Duration, error) {
	if d.MaxTTL == "" {
		return 0, nil
	}
	return time.ParseDuration(d.MaxTTL)
}

// exeAllowed matches the command exactly as written. A bare name does not
// cover a path that ends in it: /tmp/x/python3 is not python3.
func exeAllowed(allowed []string, exe string) bool {
	return slices.Contains(allowed, exe)
}

func capabilityAllowed(patterns []string, action string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, action); err == nil && ok {
			return true
		}
	}
	return false
}

// Validate checks the rules the JSON Schema cannot express.
func (d Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d, got %d", SchemaVersion, d.SchemaVersion)
	}
	if !connectionRe.MatchString(d.Connection) {
		return fmt.Errorf("connection %q must be * or a name of letters, digits, '.', '_' and '-'", d.Connection)
	}
	if d.Default != "" && d.Default != "deny" {
		return fmt.Errorf("default must be \"deny\", got %q", d.Default)
	}
	if d.MaxTTL != "" {
		ttl, err := d.TTL()
		if err != nil || ttl <= 0 {
			return fmt.Errorf("max_ttl %q must be a positive duration such as 15m", d.MaxTTL)
		}
	}
	for _, c := range d.Capabilities {
		if _, err := path.Match(c, ""); err != nil {
			return fmt.Errorf("capability %q is not a valid glob: %w", c, err)
		}
	}
	if err := validateHosts("hosts", d.Hosts); err != nil {
		return err
	}
	if d.Egress != nil {
		if err := validateHosts("egress.allow", d.Egress.Allow); err != nil {
			return err
		}
		if d.Egress.DenyPrivateRanges != nil && !*d.Egress.DenyPrivateRanges {
			return errors.New("egress.deny_private_ranges cannot be false: private, link-local and metadata ranges are never reachable")
		}
	}
	if d.FS != nil {
		for label, paths := range map[string][]string{"fs.read": d.FS.Read, "fs.write": d.FS.Write, "fs.deny": d.FS.Deny} {
			if err := validatePaths(label, paths); err != nil {
				return err
			}
		}
	}
	for i, c := range d.Commands {
		if err := c.validate(); err != nil {
			return fmt.Errorf("commands[%d]: %w", i, err)
		}
	}
	if d.Host != nil {
		if d.Host.Source == "" {
			return errors.New("host.source is required")
		}
		if err := validateHosts("host.egress_allow", d.Host.EgressAllow); err != nil {
			return err
		}
		for label, paths := range map[string][]string{"host.fs_write": d.Host.FSWrite, "host.fs_deny": d.Host.FSDeny} {
			if err := validatePaths(label, paths); err != nil {
				return err
			}
		}
	}
	for kind, rule := range d.Callers {
		if !slices.Contains(Kinds, kind) {
			return fmt.Errorf("callers.%s is not a caller kind (agent, host, service, human)", kind)
		}
		for _, r := range rule.Runtimes {
			if err := policy.ValidateRuntimeMode(r); err != nil {
				return fmt.Errorf("callers.%s: %w", kind, err)
			}
		}
		if len(rule.Units) > 0 && kind != callerkind.Service {
			return fmt.Errorf("callers.%s: units apply to service callers only", kind)
		}
		if rule.isDeny() {
			continue
		}
		if !rule.Allow && !rule.isDeny() {
			return fmt.Errorf("callers.%s: a denied caller cannot list runtimes, exe, units, tiers, approval, ttl or max_requests", kind)
		}
		if err := validTiers(kind, rule.Tiers); err != nil {
			return fmt.Errorf("callers.%s.tiers: %w", kind, err)
		}
		if rule.Approval != "" && !slices.Contains(approvalModes, rule.Approval) {
			return fmt.Errorf("callers.%s.approval %q must be one of %s", kind, rule.Approval, strings.Join(approvalModes, ", "))
		}
		if _, err := ttl(rule.TTL); err != nil {
			return fmt.Errorf("callers.%s.ttl: %w", kind, err)
		}
		if rule.MaxRequests < 0 {
			return fmt.Errorf("callers.%s.max_requests cannot be negative", kind)
		}
	}
	return nil
}

func (c CommandRule) validate() error {
	if len(c.Match) == 0 || !filepath.IsAbs(c.Match[0]) {
		return errors.New("match must start with the absolute path of the executable")
	}
	for i, m := range c.Match {
		if m == "**" && i != len(c.Match)-1 {
			return errors.New(`"**" is allowed only as the last argument`)
		}
	}
	if err := validTiers(callerkind.Human, c.Tiers); err != nil {
		return err
	}
	if c.Approval != "" && !slices.Contains(approvalModes, c.Approval) {
		return fmt.Errorf("approval %q must be one of %s", c.Approval, strings.Join(approvalModes, ", "))
	}
	if c.ExeSHA256 != "" && !sha256Re.MatchString(c.ExeSHA256) {
		return errors.New("exe_sha256 must be 64 lowercase hex digits")
	}
	return nil
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	if err := c.AddResource("connection-policy.schema.json", bytes.NewReader(schemas.ConnectionPolicy)); err != nil {
		return nil, err
	}
	return c.Compile("connection-policy.schema.json")
})

// Parse validates data against the schema and the document rules.
func Parse(data []byte) (Document, error) {
	schema, err := compiledSchema()
	if err != nil {
		return Document{}, fmt.Errorf("connection policy schema: %w", err)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return Document{}, fmt.Errorf("not valid JSON: %w", err)
	}
	if err := schema.Validate(generic); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return Document{}, fmt.Errorf("does not match the connection policy schema: %s", firstCause(ve))
		}
		return Document{}, err
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return Document{}, err
	}
	if err := d.Validate(); err != nil {
		return Document{}, err
	}
	return d, nil
}

func firstCause(ve *jsonschema.ValidationError) string {
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	loc := ve.InstanceLocation
	if loc == "" {
		loc = "document"
	}
	return fmt.Sprintf("%s: %s", loc, ve.Message)
}

// Marshal renders a document in the form Parse accepts.
func Marshal(d Document) ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
