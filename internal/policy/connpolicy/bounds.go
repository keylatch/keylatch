package connpolicy

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
)

// HostBounds are the limits an agent's own sandbox sets, recorded by
// `policy import --from`. They only ever narrow a document: egress is the
// intersection of the document's list and the host's, writes must lie inside
// the host's writable paths, and the host's denies are added to the
// document's.
type HostBounds struct {
	Source string `json:"source"`
	// EgressRestricted is set when the host names the domains it allows; an
	// empty EgressAllow then means none.
	EgressRestricted bool     `json:"egress_restricted,omitempty"`
	EgressAllow      []string `json:"egress_allow,omitempty"`
	WriteRestricted  bool     `json:"write_restricted,omitempty"`
	FSWrite          []string `json:"fs_write,omitempty"`
	FSDeny           []string `json:"fs_deny,omitempty"`
}

// PathVariables are the ${name} prefixes a document's paths may start with.
var PathVariables = []string{"project", "toolchain_caches", "keylatch_state", "browser_profiles", "harness_config"}

func validateHosts(label string, hosts []string) error {
	seen := map[string]bool{}
	for _, h := range hosts {
		if err := registry.ValidateHostPattern(h); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if seen[strings.ToLower(h)] {
			return fmt.Errorf("%s: %q appears twice", label, h)
		}
		seen[strings.ToLower(h)] = true
	}
	return nil
}

func validatePaths(label string, paths []string) error {
	for _, p := range paths {
		if err := validatePath(p); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	return nil
}

func validatePath(p string) error {
	root, _ := splitRoot(p)
	switch {
	case p == "":
		return errors.New("empty path")
	case root == "":
		return fmt.Errorf("%q must be absolute, start with ~/ or start with a ${variable}", p)
	case strings.HasPrefix(root, "${") && !slices.Contains(PathVariables, strings.TrimSuffix(strings.TrimPrefix(root, "${"), "}")):
		return fmt.Errorf("%q: unknown variable %s (use %s)", p, root, "${"+strings.Join(PathVariables, "}, ${")+"}")
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." || strings.ContainsRune(el, 0) {
			return fmt.Errorf("%q must not contain .. or a NUL byte", p)
		}
	}
	return nil
}

// splitRoot splits a path into its root ("/", "~" or "${name}") and the rest.
func splitRoot(p string) (root, rest string) {
	switch {
	case strings.HasPrefix(p, "/"):
		return "/", strings.TrimPrefix(path.Clean(p), "/")
	case p == "~" || strings.HasPrefix(p, "~/"):
		return "~", strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "~")), "/")
	case strings.HasPrefix(p, "${"):
		end := strings.Index(p, "}")
		if end < 0 {
			return "", ""
		}
		return p[:end+1], strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p[end+1:], "/")), "/")
	}
	return "", ""
}

// PathWithin reports whether child is parent or below it. Paths with different
// roots are never within one another: a variable's value is known only when
// the run starts.
func PathWithin(child, parent string) bool {
	cr, cx := splitRoot(child)
	pr, px := splitRoot(parent)
	if cr == "" || cr != pr {
		return false
	}
	return px == "" || cx == px || strings.HasPrefix(cx, px+"/")
}

// WithinAny reports whether p lies within any of the paths.
func WithinAny(p string, paths []string) bool {
	return slices.ContainsFunc(paths, func(q string) bool { return PathWithin(p, q) })
}

// IntersectPaths returns the paths both lists allow: every entry of a that lies
// within an entry of b, and every entry of b that lies within an entry of a.
func IntersectPaths(a, b []string) []string {
	var out []string
	for _, x := range a {
		if WithinAny(x, b) {
			out = append(out, x)
		}
	}
	for _, y := range b {
		if WithinAny(y, a) {
			out = append(out, y)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// UnionPaths returns every path of either list.
func UnionPaths(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// IntersectHosts returns the destinations both lists allow, as the narrower
// pattern of each overlapping pair: a literal host that a wildcard covers stays
// as the literal.
func IntersectHosts(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if m, ok := narrower(x, y); ok {
				out = append(out, m)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func normalizeAuthority(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.Contains(s, ":") {
		s += ":443"
	}
	return s
}

func isWild(s string) bool { return strings.HasPrefix(s, "*.") }

// narrower returns the pattern that matches what both a and b match, when one
// of them covers the other.
func narrower(a, b string) (string, bool) {
	na, nb := normalizeAuthority(a), normalizeAuthority(b)
	switch {
	case na == nb:
		return a, true
	case !isWild(nb) && registry.MatchAuthority(na, nb):
		return b, true
	case !isWild(na) && registry.MatchAuthority(nb, na):
		return a, true
	case isWild(na) && isWild(nb):
		// Two wildcards overlap only when one suffix lies below the other.
		if registry.MatchAuthority(na, strings.TrimPrefix(nb, "*.")) {
			return b, true
		}
		if registry.MatchAuthority(nb, strings.TrimPrefix(na, "*.")) {
			return a, true
		}
	}
	return "", false
}

// EffectiveEgress is the non-secret destinations a contained run may reach:
// the document's list, narrowed by the host's when the host names domains.
func (d Document) EffectiveEgress() []string {
	var own []string
	if d.Egress != nil {
		own = slices.Clone(d.Egress.Allow)
	}
	if d.Host != nil && d.Host.EgressRestricted {
		return IntersectHosts(own, d.Host.EgressAllow)
	}
	return own
}

// IntersectHostsIfAny narrows template by allow when allow names anything;
// an empty allow leaves the template's hosts as they are.
func IntersectHostsIfAny(template, allow []string) []string {
	if len(allow) == 0 {
		return slices.Clone(template)
	}
	return IntersectHosts(template, allow)
}

// EffectiveHosts narrows the hosts a template binds a credential to by the
// document's hosts list. Without a list the template's hosts stand.
func (d Document) EffectiveHosts(template []string) []string {
	if len(d.Hosts) == 0 {
		return slices.Clone(template)
	}
	return IntersectHosts(template, d.Hosts)
}

// EffectiveDeny is every path the document and the host both keep from a run.
func (d Document) EffectiveDeny() []string {
	var own, host []string
	if d.FS != nil {
		own = d.FS.Deny
	}
	if d.Host != nil {
		host = d.Host.FSDeny
	}
	return UnionPaths(own, host)
}

// WriteAllowed reports whether a run may write under p given the document's
// write list, with variables already expanded by the caller, and the host's.
// An empty document list allows the project alone, which the caller expresses
// by passing p as the project.
func (d Document) WriteAllowed(p string, expandedWrite []string) bool {
	if len(expandedWrite) > 0 && !WithinAny(p, expandedWrite) {
		return false
	}
	if d.Host != nil && d.Host.WriteRestricted && !WithinAny(p, d.Host.FSWrite) {
		return false
	}
	return true
}

// WithHost returns the document bounded by the host's limits, replacing any
// earlier import.
func (d Document) WithHost(b HostBounds) Document {
	d.Host = &b
	return d
}
