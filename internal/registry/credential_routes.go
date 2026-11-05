package registry

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// credentialSegments are path segments that name routes creating, reading or
// listing credentials or keys.
var credentialSegments = map[string]struct{}{
	"keys": {}, "api_keys": {}, "api-keys": {}, "apikeys": {},
	"tokens": {}, "token": {}, "access_tokens": {}, "access-tokens": {},
	"api_tokens": {}, "api-tokens": {}, "service_tokens": {}, "service-tokens": {},
	"credentials": {}, "secrets": {}, "client_secrets": {}, "private_keys": {},
	"signing_keys": {}, "passwords": {},
}

// DeniesRoute reports whether the template lists method and urlPath (a path
// without query string) in deny_routes. An entry is a path, optionally
// prefixed by a method and a space; each path segment is a glob (* matches any
// characters within the segment) and a final ** matches the rest. Trailing
// slashes and case are ignored.
func (t ConnectionTemplate) DeniesRoute(method, urlPath string) bool {
	return RouteDenied(t.DenyRoutes, method, urlPath)
}

// RouteDenied reports whether any deny_routes entry matches method and
// urlPath; see ConnectionTemplate.DeniesRoute for the entry syntax.
func RouteDenied(entries []string, method, urlPath string) bool {
	for _, entry := range entries {
		if routeMatches(entry, method, urlPath) {
			return true
		}
	}
	return false
}

func routeMatches(entry, method, urlPath string) bool {
	if m, rest, ok := strings.Cut(entry, " "); ok {
		if m != "*" && !strings.EqualFold(m, method) {
			return false
		}
		entry = rest
	}
	pat, got := splitRoute(entry), splitRoute(urlPath)
	for i, seg := range pat {
		if seg == "**" {
			return i == len(pat)-1
		}
		if i >= len(got) {
			return false
		}
		if ok, err := path.Match(seg, got[i]); err != nil || !ok {
			return false
		}
	}
	return len(pat) == len(got)
}

func splitRoute(p string) []string {
	p = strings.ToLower(strings.Trim(p, "/"))
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// isCredentialRoute reports whether urlPath looks like a route that creates,
// reads or lists credentials or keys.
func isCredentialRoute(urlPath string) bool {
	for _, seg := range splitRoute(urlPath) {
		if _, ok := credentialSegments[seg]; ok {
			return true
		}
	}
	return false
}

// exposedRoutes lists the provider routes a template makes callable: its
// actions and gateway actions.
func (t ConnectionTemplate) exposedRoutes() []exposedRoute {
	var out []exposedRoute
	for name, a := range t.Actions {
		out = append(out, exposedRoute{what: "action " + name, method: a.Method, path: a.Path})
	}
	for _, g := range t.GatewayActions {
		method := g.Method
		if method == "" {
			method = "POST"
		}
		for _, p := range []string{g.UpstreamPath, g.SDKPath} {
			if p != "" {
				out = append(out, exposedRoute{what: "gateway action " + g.Name, method: method, path: p})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].what < out[j].what })
	return out
}

type exposedRoute struct{ what, method, path string }

// ValidateDenyRoutes fails a template that exposes a credential route (a path
// that creates, reads or lists credentials or keys) which deny_routes does not
// list, and one whose own deny_routes entry covers a route it exposes.
func ValidateDenyRoutes(t ConnectionTemplate) error {
	for _, r := range t.exposedRoutes() {
		denied := t.DeniesRoute(r.method, r.path)
		switch {
		case isCredentialRoute(r.path) && !denied:
			return fmt.Errorf("provider %q: %s exposes credential route %s %s without a deny_routes entry", t.Provider, r.what, r.method, r.path)
		case denied:
			return fmt.Errorf("provider %q: %s exposes %s %s, which deny_routes refuses", t.Provider, r.what, r.method, r.path)
		}
	}
	return nil
}
