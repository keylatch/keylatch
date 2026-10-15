// Package connpolicy is the per-connection policy document: which caller
// kinds may use a connection, under which runtimes and executables. It
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
	SchemaVersion int                            `json:"schema_version"`
	Description   string                         `json:"description,omitempty"`
	Connection    string                         `json:"connection"`
	Default       string                         `json:"default,omitempty"`
	Capabilities  []string                       `json:"capabilities,omitempty"`
	MaxTTL        string                         `json:"max_ttl,omitempty"`
	Callers       map[callerkind.Kind]CallerRule `json:"callers,omitempty"`
}

// CallerRule says whether a caller kind may use the connection. The zero value
// denies.
type CallerRule struct {
	Allow    bool
	Runtimes []string
	Exe      []string
	Units    []string
}

type callerRuleObject struct {
	Allow    bool     `json:"allow"`
	Runtimes []string `json:"runtimes,omitempty"`
	Exe      []string `json:"exe,omitempty"`
	Units    []string `json:"units,omitempty"`
}

// MarshalJSON writes a denying rule as the string "deny".
func (r CallerRule) MarshalJSON() ([]byte, error) {
	if !r.Allow && len(r.Runtimes) == 0 && len(r.Exe) == 0 && len(r.Units) == 0 {
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
}

// Decision is a document's verdict.
type Decision struct {
	Allow  bool
	Reason string
	MaxTTL time.Duration
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
	ttl, _ := d.TTL()
	return Decision{Allow: true, MaxTTL: ttl}
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
		if !rule.Allow && (len(rule.Runtimes) > 0 || len(rule.Exe) > 0 || len(rule.Units) > 0) {
			return fmt.Errorf("callers.%s: a denied caller cannot list runtimes, exe or units", kind)
		}
	}
	return nil
}

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
