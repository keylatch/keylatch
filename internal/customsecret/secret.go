package customsecret

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/store"
)

const (
	// Category is the storage category and registry category of custom secrets.
	Category = "custom"
	// ValueField is the stored field holding the value or reference.
	ValueField = "value"
	// Capability is the single gateway capability a custom secret grants.
	Capability = "request"
)

// Injection says where the credential is placed on the upstream request.
type Injection struct {
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Format string `json:"format,omitempty"`
}

// Secret is the metadata of one custom secret. It never holds the value.
type Secret struct {
	Name       string    `json:"name"`
	Hosts      []string  `json:"hosts"`
	Paths      []string  `json:"paths"`
	Methods    []string  `json:"methods,omitempty"`
	Injection  Injection `json:"injection"`
	BaseURLEnv string    `json:"base_url_env,omitempty"`
	// RefScheme is the external-store scheme (op, aws-sm, hashivault) when the
	// stored value is a reference; empty when keylatch stores the value itself.
	RefScheme string    `json:"ref_scheme,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// Status is StatusPending for an entry an agent session added that the
	// owner has not approved; such an entry has no active rules and is never routed.
	Status string `json:"status,omitempty"`
	// Proposed is a change an agent session asked for. The active rules above
	// keep serving until the owner approves it.
	Proposed *Secret `json:"proposed,omitempty"`
	// NewValue marks a proposal that carries a value or reference, held at PendingPath.
	NewValue bool `json:"new_value,omitempty"`
}

// StatusPending marks an entry that has never been approved.
const StatusPending = "pending"

// Active reports whether the entry's own rules are approved and may be routed.
func (s Secret) Active() bool { return s.Status != StatusPending }

// State is a short label for list output.
func (s Secret) State() string {
	switch {
	case !s.Active():
		return "pending approval"
	case s.Proposed != nil:
		return "active, change pending"
	}
	return "active"
}

// Shown returns the rules worth displaying: the proposal for a never-approved entry, else the entry.
func (s Secret) Shown() Secret {
	if !s.Active() && s.Proposed != nil {
		p := *s.Proposed
		p.Status, p.Proposed = s.Status, s.Proposed
		return p
	}
	return s
}

// PendingPath is the backend path of a proposed value or reference. The
// gateway only reads ValuePath, so a pending value is never served.
func PendingPath(name string) string {
	return "default/" + Category + "/" + name + "/pending"
}

// ValuePath is the backend path of the secret's value or reference.
func ValuePath(name string) string {
	return "default/" + Category + "/" + name + "/" + ValueField
}

// RefSchemeOf returns the scheme of a validated external-store reference.
func RefSchemeOf(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if err := store.ValidateProviderRefURI(ref); err != nil {
		return "", err
	}
	scheme, _, _ := strings.Cut(ref, "://")
	return scheme, nil
}

// Kind is a short human description of the injection, never the format.
func (s Secret) Kind() string {
	switch s.Injection.Kind {
	case InjectHeader:
		return "header " + s.Injection.Name
	case InjectQuery:
		return "query " + s.Injection.Name
	case InjectBasic:
		return "basic auth user " + s.Injection.Name
	}
	return s.Injection.Kind
}

// Source describes where the value comes from: the reference scheme or "stored".
func (s Secret) Source() string {
	if s.RefScheme != "" {
		return s.RefScheme + " reference"
	}
	return "stored"
}

// Normalize validates the secret and rewrites it into canonical form.
// It does not check name collisions with provider templates; see Check.
func (s *Secret) Normalize() error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if len(s.Hosts) == 0 {
		return errors.New("at least one --host is required")
	}
	hosts := make([]string, 0, len(s.Hosts))
	seen := map[string]bool{}
	for _, h := range s.Hosts {
		n, err := NormalizeHost(h)
		if err != nil {
			return err
		}
		if !seen[n] {
			seen[n] = true
			hosts = append(hosts, n)
		}
	}
	s.Hosts = hosts

	paths := s.Paths
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	s.Paths = make([]string, 0, len(paths))
	for _, p := range paths {
		n, err := NormalizePath(p)
		if err != nil {
			return err
		}
		s.Paths = append(s.Paths, n)
	}
	sort.Strings(s.Paths)

	var methods []string
	for _, m := range s.Methods {
		n, err := NormalizeMethod(m)
		if err != nil {
			return err
		}
		methods = append(methods, n)
	}
	if len(methods) == 0 {
		methods = append([]string(nil), DefaultMethods...)
	}
	s.Methods = methods

	if err := s.Injection.validate(); err != nil {
		return err
	}
	if s.BaseURLEnv != "" {
		if err := ValidateBaseURLEnv(s.BaseURLEnv); err != nil {
			return err
		}
	}
	return nil
}

// Check rejects a secret whose name is already a registered provider or custom secret.
func Check(name string) error {
	if _, err := registry.Get(name); err == nil {
		return fmt.Errorf("name %q is already used by a provider or custom secret", name)
	}
	return nil
}

// Template builds the in-memory provider template that routes the secret through the gateway.
func (s Secret) Template() registry.ConnectionTemplate {
	placement := registry.AuthPlacement{In: s.Injection.Kind, Name: s.Injection.Name, Format: s.Injection.Format}
	return registry.ConnectionTemplate{
		Provider:       s.Name,
		DisplayName:    s.Name,
		Category:       Category,
		Description:    "Custom secret for " + s.Hosts[0],
		SecretFields:   []registry.SecretField{{Name: ValueField, Label: "Value", Required: true, Sensitive: true, SecretKind: "api_key"}},
		AuthFlow:       registry.AuthCustom,
		AuthPlacement:  placement,
		StoragePathTpl: "{{namespace}}/" + Category + "/{{provider}}",
		TrustLevel:     registry.TrustLocalOnly,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewaySDK,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK, registry.RuntimeGatewayProxy},
		},
		Capabilities:   []registry.Capability{{Name: Capability, Description: "Forward requests to " + s.Hosts[0]}},
		InjectionRules: []registry.InjectionRule{{Source: ValueField}},
		Custom: &registry.CustomEndpoint{
			Hosts:      append([]string(nil), s.Hosts...),
			Paths:      append([]string(nil), s.Paths...),
			Methods:    append([]string(nil), s.Methods...),
			BaseURLEnv: s.BaseURLEnv,
		},
	}
}

// RegisterAll adds every secret to the provider registry and the gateway SSRF
// allowlist. A secret that is invalid or whose name collides with a provider
// is skipped and reported; the others still register.
func RegisterAll(secrets []Secret) []error {
	var errs []error
	for _, s := range secrets {
		if !s.Active() {
			continue
		}
		if err := s.Normalize(); err != nil {
			errs = append(errs, fmt.Errorf("custom secret %q: %w", s.Name, err))
			continue
		}
		if existing, err := registry.Get(s.Name); err == nil && existing.Custom == nil {
			errs = append(errs, fmt.Errorf("custom secret %q: name is already a provider template", s.Name))
			continue
		}
		tmpl := s.Template()
		if err := registry.Register(tmpl); err != nil {
			errs = append(errs, fmt.Errorf("custom secret %q: %w", s.Name, err))
			continue
		}
		registry.AllowProviderHosts(s.Name, s.Hosts)
	}
	return errs
}
