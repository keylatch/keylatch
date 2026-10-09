package registry

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// CustomBinding is the binding a connection declares for itself when its
// provider has no template.
type CustomBinding struct {
	Hosts []string          `json:"hosts"`
	Slots []Slot            `json:"slots"`
	Shape PlaceholderShape  `json:"placeholder_shape"`
	Env   map[string]string `json:"env"`
}

// DefaultCustomMinLength is the placeholder length used when none is declared.
const DefaultCustomMinLength = 32

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate applies the template binding rules to a custom binding whose
// secret is made of the given fields.
func (c CustomBinding) Validate(name string, fields []string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("custom connection %q bindings: %s", name, fmt.Sprintf(format, a...))
	}
	if len(c.Slots) == 0 {
		return fail("slots required")
	}
	if c.Shape.MinLength <= 0 {
		return fail("placeholder_shape.min_length required")
	}
	if len(c.Env) == 0 {
		return fail("env required")
	}
	for f, e := range c.Env {
		if !slices.Contains(fields, f) {
			return fail("env for unknown secret field %q", f)
		}
		if !envNamePattern.MatchString(e) {
			return fail("invalid env name %q", e)
		}
	}
	t := ConnectionTemplate{
		Provider:         name,
		Hosts:            c.Hosts,
		Slots:            c.Slots,
		PlaceholderShape: c.Shape,
		EnvClass:         EnvClassSpec{Default: EnvProd},
	}
	for _, f := range fields {
		t.SecretFields = append(t.SecretFields, SecretField{Name: f})
	}
	return ValidateBindings(t)
}

// Binding returns the contract through the same API templates use.
func (c CustomBinding) Binding(name string) Binding {
	return Binding{
		Provider: name,
		Hosts:    c.Hosts,
		Slots:    c.Slots,
		Shape:    c.Shape,
		EnvClass: EnvClassSpec{Default: EnvProd},
		Env:      c.Env,
	}
}

// WidenedBy reports whether next grants more than c: a host or slot c lacks.
func (c CustomBinding) WidenedBy(next CustomBinding) bool {
	for _, h := range next.Hosts {
		if !slices.Contains(c.Hosts, h) {
			return true
		}
	}
	for _, s := range next.Slots {
		if !slices.ContainsFunc(c.Slots, func(o Slot) bool { return slotCovers(o, s) }) {
			return true
		}
	}
	return false
}

func slotCovers(old, next Slot) bool {
	if old.Field != next.Field || old.In != next.In || old.Name != next.Name ||
		old.Scheme != next.Scheme || old.Part != next.Part {
		return false
	}
	for _, h := range next.Hosts {
		if !slices.Contains(old.Hosts, h) {
			return false
		}
	}
	return true
}

// ParseSlot parses "header:Name[:Scheme]", "query:name" or "basic:user|password",
// optionally prefixed "field=". An empty Field means the connection's only field.
func ParseSlot(spec string) (Slot, error) {
	var s Slot
	if f, rest, ok := strings.Cut(spec, "="); ok && !strings.Contains(f, ":") {
		s.Field, spec = f, rest
	}
	parts := strings.Split(spec, ":")
	switch SlotLocation(parts[0]) {
	case SlotHeader:
		if len(parts) < 2 || len(parts) > 3 {
			return s, fmt.Errorf("invalid slot %q: want header:Name[:Scheme]", spec)
		}
		s.In, s.Name = SlotHeader, parts[1]
		if len(parts) == 3 {
			s.Scheme = parts[2]
		}
	case SlotQuery:
		if len(parts) != 2 {
			return s, fmt.Errorf("invalid slot %q: want query:name", spec)
		}
		s.In, s.Name = SlotQuery, parts[1]
	case SlotBasic:
		if len(parts) != 2 {
			return s, fmt.Errorf("invalid slot %q: want basic:user|password", spec)
		}
		s.In, s.Part = SlotBasic, parts[1]
	default:
		return s, fmt.Errorf("invalid slot %q: location must be header, query or basic", spec)
	}
	return s, nil
}

// Extract returns the value a client placed in the slot of r. Header names and
// schemes match case-insensitively, as HTTP clients differ in how they send them.
func (s Slot) Extract(r *http.Request) (string, bool) {
	switch s.In {
	case SlotHeader:
		v := r.Header.Get(s.Name)
		if s.Scheme == "" {
			return v, v != ""
		}
		scheme, rest, ok := strings.Cut(v, " ")
		if !ok || !strings.EqualFold(scheme, s.Scheme) || rest == "" {
			return "", false
		}
		return rest, true
	case SlotQuery:
		v := r.URL.Query().Get(s.Name)
		return v, v != ""
	case SlotBasic:
		user, pass, ok := r.BasicAuth()
		if !ok {
			return "", false
		}
		if s.Part == BasicUser {
			return user, user != ""
		}
		return pass, pass != ""
	}
	return "", false
}
