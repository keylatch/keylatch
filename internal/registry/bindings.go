package registry

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// SlotLocation is where in a request a secret may be substituted.
type SlotLocation string

const (
	SlotHeader SlotLocation = "header"
	SlotQuery  SlotLocation = "query"
	SlotBasic  SlotLocation = "basic"
)

// BasicPart selects the user or password half of an HTTP Basic credential.
const (
	BasicUser     = "user"
	BasicPassword = "password"
)

// EnvClass classifies a credential as pointing at a test, dev or production environment.
type EnvClass string

const (
	EnvTest EnvClass = "test"
	EnvDev  EnvClass = "dev"
	EnvProd EnvClass = "prod"
)

// Slot is one request position where a secret field may be substituted, and
// the authorities it may be substituted toward.
type Slot struct {
	Field  string       `json:"field"            yaml:"field"`
	In     SlotLocation `json:"in"               yaml:"in"`
	Name   string       `json:"name,omitempty"   yaml:"name,omitempty"`
	Scheme string       `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Part   string       `json:"part,omitempty"   yaml:"part,omitempty"`
	Hosts  []string     `json:"hosts"            yaml:"hosts"`
}

// PlaceholderShape makes a placeholder pass client-library format checks.
type PlaceholderShape struct {
	Prefix    string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	MinLength int    `json:"min_length"       yaml:"min_length"`
}

// AdapterKind names a protocol adapter that authenticates upstream on behalf of the child.
type AdapterKind string

const (
	AdapterPostgres         AdapterKind = "postgres"
	AdapterMySQL            AdapterKind = "mysql"
	AdapterRedis            AdapterKind = "redis"
	AdapterSSHAgent         AdapterKind = "ssh_agent"
	AdapterGitCredential    AdapterKind = "git_credential"    //nolint:gosec // adapter name, not a credential
	AdapterDockerCredential AdapterKind = "docker_credential" //nolint:gosec // adapter name, not a credential
)

var validAdapterKinds = map[AdapterKind]struct{}{
	AdapterPostgres: {}, AdapterMySQL: {}, AdapterRedis: {}, AdapterSSHAgent: {},
	AdapterGitCredential: {}, AdapterDockerCredential: {},
}

// Adapter binds a secret field to a non-HTTP-slot protocol adapter.
type Adapter struct {
	Kind  AdapterKind `json:"kind"  yaml:"kind"`
	Field string      `json:"field" yaml:"field"`
	Hosts []string    `json:"hosts" yaml:"hosts"`
	// Username is the account name a credential helper returns beside the placeholder.
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
}

// EnvClassSpec derives a credential's environment class from its value prefix.
type EnvClassSpec struct {
	Default  EnvClass            `json:"default"             yaml:"default"`
	ByPrefix map[string]EnvClass `json:"by_prefix,omitempty" yaml:"by_prefix,omitempty"`
}

// Binding is the substitution contract of a provider template.
type Binding struct {
	Provider string
	Hosts    []string
	Slots    []Slot
	Shape    PlaceholderShape
	Adapter  Adapter
	EnvClass EnvClassSpec
}

// Binding returns the template's binding contract; ok is false when it declares none.
func (t ConnectionTemplate) Binding() (Binding, bool) {
	if len(t.Hosts) == 0 && len(t.Slots) == 0 && t.Adapter.Kind == "" {
		return Binding{}, false
	}
	return Binding{
		Provider: t.Provider,
		Hosts:    t.Hosts,
		Slots:    t.Slots,
		Shape:    t.PlaceholderShape,
		Adapter:  t.Adapter,
		EnvClass: t.EnvClass,
	}, true
}

// IsMinted reports whether the field is produced by Keylatch at use time
// instead of being read from the store.
func (t ConnectionTemplate) IsMinted(field string) bool {
	return slices.Contains(t.MintedFields, field)
}

// BindingFor returns the binding contract of a registered provider.
func BindingFor(provider string) (Binding, error) {
	t, err := Get(provider)
	if err != nil {
		return Binding{}, err
	}
	b, ok := t.Binding()
	if !ok {
		return Binding{}, fmt.Errorf("registry: provider %q declares no host bindings", provider)
	}
	return b, nil
}

// AllowsHost reports whether the authority is one of the binding's hosts.
func (b Binding) AllowsHost(authority string) bool {
	return matchAny(b.Hosts, authority)
}

// SlotsFor returns the slots for a secret field that may be substituted toward the authority.
func (b Binding) SlotsFor(field, authority string) []Slot {
	var out []Slot
	for _, s := range b.Slots {
		if s.Field == field && matchAny(s.Hosts, authority) {
			out = append(out, s)
		}
	}
	return out
}

// Wrap builds a placeholder from a random token that satisfies the shape.
func (p PlaceholderShape) Wrap(token string) string {
	v := p.Prefix + token
	if n := p.MinLength - len(v); n > 0 {
		v += strings.Repeat("x", n)
	}
	return v
}

// Matches reports whether v satisfies the shape.
func (p PlaceholderShape) Matches(v string) bool {
	return strings.HasPrefix(v, p.Prefix) && len(v) >= p.MinLength
}

// Classify returns the environment class of a secret value; the longest matching prefix wins.
func (c EnvClassSpec) Classify(secret string) EnvClass {
	best, class := -1, c.Default
	for prefix, cl := range c.ByPrefix {
		if strings.HasPrefix(secret, prefix) && len(prefix) > best {
			best, class = len(prefix), cl
		}
	}
	return class
}

// MatchAuthority reports whether authority (host[:port], port defaults to 443)
// matches pattern. A leading "*." matches one or more labels below the suffix,
// never the suffix itself.
func MatchAuthority(pattern, authority string) bool {
	ph, pp, ok := splitAuthority(pattern)
	if !ok {
		return false
	}
	ah, ap, ok := splitAuthority(authority)
	if !ok || pp != ap {
		return false
	}
	if suffix, wild := strings.CutPrefix(ph, "*."); wild {
		return strings.HasSuffix(ah, "."+suffix) && len(ah) > len(suffix)+1
	}
	return ph == ah
}

func matchAny(patterns []string, authority string) bool {
	for _, p := range patterns {
		if MatchAuthority(p, authority) {
			return true
		}
	}
	return false
}

func splitAuthority(a string) (host, port string, ok bool) {
	a = strings.ToLower(strings.TrimSpace(a))
	if a == "" || strings.ContainsAny(a, "/@ ") {
		return "", "", false
	}
	host, port = a, "443"
	if h, p, err := net.SplitHostPort(a); err == nil {
		host, port = h, p
	} else if strings.Contains(a, ":") {
		return "", "", false
	}
	if host == "" || port == "" || strings.HasSuffix(host, ".") {
		return "", "", false
	}
	return host, port, true
}

// coreProviders must declare complete bindings before they can be registered.
var coreProviders = map[string]struct{}{
	"github": {}, "vercel": {}, "supabase": {}, "stripe": {}, "openai": {}, "anthropic": {},
}

// RequiresBindings reports whether the provider must declare bindings.
func RequiresBindings(provider string) bool {
	_, ok := coreProviders[provider]
	return ok
}

// ValidateBindings checks a template's binding declarations. Core providers
// must declare hosts, slots, a placeholder shape and an environment class.
func ValidateBindings(t ConnectionTemplate) error {
	declared := len(t.Hosts) > 0 || len(t.Slots) > 0 || t.Adapter.Kind != "" ||
		t.PlaceholderShape != (PlaceholderShape{}) || t.EnvClass.Default != ""
	required := RequiresBindings(t.Provider)
	if !declared && !required {
		return nil
	}
	fail := func(format string, a ...any) error {
		return fmt.Errorf("provider %q bindings: %s", t.Provider, fmt.Sprintf(format, a...))
	}
	if len(t.Hosts) == 0 {
		return fail("hosts required")
	}
	for _, h := range t.Hosts {
		if err := validHostPattern(h); err != nil {
			return fail("%v", err)
		}
	}
	if required {
		if len(t.Slots) == 0 {
			return fail("slots required")
		}
		if t.PlaceholderShape.MinLength <= 0 {
			return fail("placeholder_shape.min_length required")
		}
		if t.EnvClass.Default == "" {
			return fail("env_class.default required")
		}
	}
	fields := map[string]struct{}{}
	for _, f := range t.SecretFields {
		fields[f.Name] = struct{}{}
	}
	for _, f := range t.MintedFields {
		if _, dup := fields[f]; dup {
			return fail("minted field %q is also a secret field", f)
		}
		fields[f] = struct{}{}
	}
	for i, s := range t.Slots {
		if _, ok := fields[s.Field]; !ok {
			return fail("slot %d: unknown secret field %q", i, s.Field)
		}
		switch s.In {
		case SlotHeader:
			if s.Name == "" || s.Part != "" {
				return fail("slot %d: header slot needs name and no part", i)
			}
		case SlotQuery:
			if s.Name == "" || s.Scheme != "" || s.Part != "" {
				return fail("slot %d: query slot needs only name", i)
			}
		case SlotBasic:
			if s.Part != BasicUser && s.Part != BasicPassword || s.Name != "" || s.Scheme != "" {
				return fail("slot %d: basic slot needs part user or password only", i)
			}
		default:
			return fail("slot %d: invalid location %q", i, s.In)
		}
		if err := subsetOf(s.Hosts, t.Hosts); err != nil {
			return fail("slot %d: %v", i, err)
		}
	}
	if t.Adapter.Kind != "" {
		if _, ok := validAdapterKinds[t.Adapter.Kind]; !ok {
			return fail("unknown adapter %q", t.Adapter.Kind)
		}
		if _, ok := fields[t.Adapter.Field]; !ok {
			return fail("adapter: unknown secret field %q", t.Adapter.Field)
		}
		if err := subsetOf(t.Adapter.Hosts, t.Hosts); err != nil {
			return fail("adapter: %v", err)
		}
	}
	if t.PlaceholderShape.MinLength < 0 || t.PlaceholderShape.MinLength < len(t.PlaceholderShape.Prefix) {
		return fail("placeholder_shape.min_length shorter than prefix")
	}
	if t.EnvClass.Default != "" && !validEnvClass(t.EnvClass.Default) {
		return fail("invalid env_class.default %q", t.EnvClass.Default)
	}
	for p, c := range t.EnvClass.ByPrefix {
		if p == "" || !validEnvClass(c) {
			return fail("invalid env_class.by_prefix entry %q", p)
		}
	}
	return nil
}

func validEnvClass(c EnvClass) bool { return c == EnvTest || c == EnvDev || c == EnvProd }

func validHostPattern(p string) error {
	h, _, ok := splitAuthority(p)
	if !ok {
		return fmt.Errorf("invalid host %q", p)
	}
	if suffix, wild := strings.CutPrefix(h, "*."); wild {
		if !strings.Contains(suffix, ".") || strings.Contains(suffix, "*") {
			return fmt.Errorf("invalid wildcard host %q", p)
		}
		return nil
	}
	if strings.Contains(h, "*") {
		return fmt.Errorf("invalid wildcard host %q", p)
	}
	return nil
}

func subsetOf(sub, all []string) error {
	if len(sub) == 0 {
		return fmt.Errorf("hosts required")
	}
	set := map[string]struct{}{}
	for _, h := range all {
		set[h] = struct{}{}
	}
	for _, h := range sub {
		if _, ok := set[h]; !ok {
			return fmt.Errorf("host %q not in template hosts", h)
		}
	}
	return nil
}
