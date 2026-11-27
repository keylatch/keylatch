// Package route compiles registry GatewayActions into a gateway route table.
//
// Implements a simple map-based router (not a full trie library).
// SDK facade routes are explicit-only; unknown paths → 404.
package route

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
)

// Sentinel errors.
var (
	ErrNoRoute                = errors.New("route: no matching route")
	ErrUnsupportedSDKEndpoint = errors.New("route: unsupported SDK endpoint")
	ErrMethodNotAllowed       = errors.New("route: method not allowed")
)

// highRiskLabels is the set of risk labels that trigger LLMSessionDeny by default.
var highRiskLabels = map[string]struct{}{
	"destructive":   {},
	"financial":     {},
	"communication": {},
	"admin":         {},
}

// defaultMaxBodyBytes is 10 MiB.
const defaultMaxBodyBytes int64 = 10 * 1024 * 1024

// Route is one compiled provider action.
type Route struct {
	Capability             string
	Provider               string
	Method                 string // HTTP method for this route (e.g. "GET", "POST"); defaults to "POST" when empty
	PathTemplate           string // "/api/<provider>/<action.Name>"
	SDKPath                string // "/sdk/<provider>/v1/<sdk_path>" (if any)
	UpstreamHost           string
	UpstreamPath           string
	AuthPlacement          registry.AuthPlacement
	AllowedParams          map[string]bool
	RiskLabel              string
	ApprovalReqd           bool
	Redaction              []registry.RedactionRule
	ExchangeStrategy       registry.ExchangeStrategy
	MaskingProfile         string
	AllowedFields          []string
	MaxBodyBytes           int64
	LLMSessionDeny         bool
	UntrustedContentSource string
	// SecretRef is the vault path for the provider root credential.
	// Built from the template's first InjectionRule source field during Compile.
	SecretRef string
	// Custom is set for user-defined secrets, whose upstream path and method
	// come from the request instead of a fixed action.
	Custom *registry.CustomEndpoint
}

// Request is the incoming gateway request relevant to routing.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Query  url.Values
	Body   []byte
	CWD    string
	Argv   []string
}

// Router holds compiled routes.
type Router struct {
	routes    map[string]*Route // key: "METHOD /path"
	sdkRoutes map[string]*Route
	custom    map[string]*Route // key: provider name
}

// Compile builds a Router from a slice of ConnectionTemplates.
//
// For each template with RuntimeSupport.Preferred in {gateway_typed, gateway_sdk}:
//
//	For each GatewayAction:
//	  - path = "/api/<provider>/<action.Name>"
//	  - SDK path = "/sdk/<provider>/v1/<sdk_path>" (only for gateway_sdk templates)
//	  - Method = action.Method (default "POST")
//	  - UpstreamHost = from template's TestStrategy endpoint URL host
//	  - UpstreamPath = from template's TestStrategy endpoint URL path
//	  - Capability = "<provider>.<action.Name>"
//	  - LLMSessionDeny = action.LLMSessionDeny OR (action.RiskLabel in {destructive,financial,communication,admin})
func Compile(templates []registry.ConnectionTemplate) (*Router, error) {
	r := &Router{
		routes:    make(map[string]*Route),
		sdkRoutes: make(map[string]*Route),
		custom:    make(map[string]*Route),
	}

	for _, tmpl := range templates {
		if tmpl.Custom != nil {
			r.custom[tmpl.Provider] = customRoute(tmpl)
			continue
		}

		// Only compile gateway-supporting templates.
		pref := tmpl.RuntimeSupport.Preferred
		if pref != registry.RuntimeGatewayTyped &&
			pref != registry.RuntimeGatewaySDK &&
			pref != registry.RuntimeGatewayProxy {
			// Also include if Supported list contains a gateway mode.
			hasGateway := false
			for _, m := range tmpl.RuntimeSupport.Supported {
				if m == registry.RuntimeGatewayTyped || m == registry.RuntimeGatewaySDK {
					hasGateway = true
					break
				}
			}
			if !hasGateway {
				continue
			}
		}

		// Parse upstream host and path from TestStrategy endpoint.
		upstreamHost, upstreamPath := parseEndpoint(tmpl.TestStrategy.Endpoint)

		for _, action := range tmpl.GatewayActions {
			path := "/api/" + tmpl.Provider + "/" + action.Name

			// HTTP method: use action.Method, default to POST.
			method := action.Method
			if method == "" {
				method = "POST"
			}

			// LLMSessionDeny: explicit OR high-risk label.
			llmDeny := action.LLMSessionDeny
			if _, isHigh := highRiskLabels[action.RiskLabel]; isHigh {
				llmDeny = true
			}

			// Masking profile default.
			maskProfile := action.MaskingProfile
			if maskProfile == "" {
				maskProfile = "basic"
			}

			// Exchange strategy default.
			exchStrategy := action.ExchangeStrategy
			if exchStrategy == "" {
				exchStrategy = registry.ExchangeStaticGatewayOnly
			}

			// UpstreamPath: use action.UpstreamPath when non-empty.
			routeUpstreamPath := upstreamPath
			if action.UpstreamPath != "" {
				routeUpstreamPath = action.UpstreamPath
			}

			route := &Route{
				Capability:       tmpl.Provider + "." + action.Name,
				Provider:         tmpl.Provider,
				Method:           method,
				PathTemplate:     path,
				UpstreamHost:     upstreamHost,
				UpstreamPath:     routeUpstreamPath,
				AuthPlacement:    tmpl.AuthPlacement,
				RiskLabel:        action.RiskLabel,
				Redaction:        tmpl.Redaction,
				ExchangeStrategy: exchStrategy,
				MaskingProfile:   maskProfile,
				AllowedFields:    action.AllowedFields,
				MaxBodyBytes:     defaultMaxBodyBytes,
				LLMSessionDeny:   llmDeny,
				SecretRef:        vaultSecretRef(tmpl),
			}
			if action.UntrustedContentSource {
				route.UntrustedContentSource = tmpl.Provider
			}

			key := method + " " + path
			r.routes[key] = route

			// SDK path for gateway_sdk templates.
			if pref == registry.RuntimeGatewaySDK || isSDKSupported(tmpl) {
				sdkPath := action.SDKPath
				if sdkPath == "" {
					sdkPath = "/sdk/" + tmpl.Provider + "/v1/" + action.Name
				}
				route2 := *route
				route2.SDKPath = sdkPath
				route2.PathTemplate = sdkPath
				sdkKey := method + " " + sdkPath
				r.sdkRoutes[sdkKey] = &route2
			}
		}

		// If no explicit GatewayActions but template has gateway support,
		// synthesise a default route from capabilities.
		if len(tmpl.GatewayActions) == 0 {
			upHost, upPath := parseEndpoint(tmpl.TestStrategy.Endpoint)
			isSDK := pref == registry.RuntimeGatewaySDK || isSDKSupported(tmpl)
			for _, cap := range tmpl.Capabilities {
				actionName := strings.ReplaceAll(cap.Name, " ", "_")
				path := "/api/" + tmpl.Provider + "/" + actionName
				rt := &Route{
					Capability:       tmpl.Provider + "." + cap.Name,
					Provider:         tmpl.Provider,
					Method:           "POST",
					PathTemplate:     path,
					UpstreamHost:     upHost,
					UpstreamPath:     upPath,
					AuthPlacement:    tmpl.AuthPlacement,
					Redaction:        tmpl.Redaction,
					ExchangeStrategy: registry.ExchangeStaticGatewayOnly,
					MaskingProfile:   "basic",
					MaxBodyBytes:     defaultMaxBodyBytes,
					SecretRef:        vaultSecretRef(tmpl),
				}
				r.routes["POST "+path] = rt

				// Also register SDK path for gateway_sdk templates.
				if isSDK {
					sdkPath := "/sdk/" + tmpl.Provider + "/v1/" + actionName
					rtSDK := *rt
					rtSDK.SDKPath = sdkPath
					rtSDK.PathTemplate = sdkPath
					r.sdkRoutes["POST "+sdkPath] = &rtSDK
				}
			}
		}

	}

	return r, nil
}

// Match returns the Route matching the given method and path.
// Returns (nil, false) if no route exists.
// Only explicitly-compiled routes match; unknown paths → (nil, false).
func (r *Router) Match(method, path string) (*Route, bool) {
	key := method + " " + path
	if rt, ok := r.routes[key]; ok {
		return rt, true
	}
	if rt, ok := r.sdkRoutes[key]; ok {
		return rt, true
	}
	return r.matchCustom(method, path)
}

// customRoute is the route of a user-defined secret. LLM sessions may use it
// within the secret's hosts, paths and methods, like a built-in non-high-risk action.
func customRoute(tmpl registry.ConnectionTemplate) *Route {
	return &Route{
		Capability:       tmpl.Provider + ".request",
		Provider:         tmpl.Provider,
		PathTemplate:     "/sdk/" + tmpl.Provider + "/v1/",
		UpstreamHost:     tmpl.Custom.Hosts[0],
		AuthPlacement:    tmpl.AuthPlacement,
		RiskLabel:        "custom",
		ExchangeStrategy: registry.ExchangeStaticGatewayOnly,
		MaskingProfile:   "basic",
		MaxBodyBytes:     defaultMaxBodyBytes,
		SecretRef:        vaultSecretRef(tmpl),
		Custom:           tmpl.Custom,
	}
}

// matchCustom resolves /sdk/<name>/v1/<path> (first host) and
// /sdk/<name>/h/<host>/<path> (any listed host) for a user-defined secret. The
// host segment must equal a listed host exactly: no case folding, trailing dot,
// port, userinfo or IP form is accepted. The returned route is a per-request
// copy carrying the upstream host, path and method.
func (r *Router) matchCustom(method, reqPath string) (*Route, bool) {
	rest, ok := strings.CutPrefix(reqPath, "/sdk/")
	if !ok {
		return nil, false
	}
	name, tail, ok := strings.Cut(rest, "/")
	if !ok {
		return nil, false
	}
	base, ok := r.custom[name]
	if !ok {
		return nil, false
	}
	var host, upstream string
	switch {
	case strings.HasPrefix(tail, "v1/"):
		host, upstream = base.Custom.Hosts[0], "/"+strings.TrimPrefix(tail, "v1/")
	case strings.HasPrefix(tail, "h/"):
		h, p, found := strings.Cut(strings.TrimPrefix(tail, "h/"), "/")
		if !found || !contains(base.Custom.Hosts, h) {
			return nil, false
		}
		host, upstream = h, "/"+p
	default:
		return nil, false
	}
	// A non-canonical path (dot or empty segments) could slip past the prefix check.
	if upstream != "/" && path.Clean(upstream) != strings.TrimSuffix(upstream, "/") {
		return nil, false
	}
	if !customMethodAllowed(base.Custom.Methods, method) {
		return nil, false
	}
	if !pathAllowed(base.Custom.Paths, upstream) {
		return nil, false
	}
	rt := *base
	rt.Method = method
	rt.UpstreamHost = host
	rt.UpstreamPath = upstream
	return &rt, true
}

// defaultCustomMethods apply when a custom secret lists none. TRACE and CONNECT
// are never allowed, even when listed.
var defaultCustomMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

func customMethodAllowed(listed []string, method string) bool {
	if method == "TRACE" || method == "CONNECT" {
		return false
	}
	if len(listed) == 0 {
		listed = defaultCustomMethods
	}
	return contains(listed, method)
}

// pathAllowed reports whether p equals an allowed prefix or sits below it on a segment boundary.
func pathAllowed(prefixes []string, p string) bool {
	for _, pre := range prefixes {
		if pre == "/" || p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// Routes returns all compiled routes.
func (r *Router) Routes() []*Route {
	all := make([]*Route, 0, len(r.routes)+len(r.sdkRoutes)+len(r.custom))
	for _, rt := range r.custom {
		all = append(all, rt)
	}
	for _, rt := range r.routes {
		all = append(all, rt)
	}
	for _, rt := range r.sdkRoutes {
		all = append(all, rt)
	}
	return all
}

// parseEndpoint extracts host and path from a URL string.
// Returns ("", "") on parse failure.
func parseEndpoint(endpoint string) (host, path string) {
	if endpoint == "" {
		return "", ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", ""
	}
	return u.Host, u.Path
}

// isSDKSupported returns true if the template supports gateway_sdk in its Supported list.
func isSDKSupported(tmpl registry.ConnectionTemplate) bool {
	for _, m := range tmpl.RuntimeSupport.Supported {
		if m == registry.RuntimeGatewaySDK {
			return true
		}
	}
	return false
}

// vaultSecretRef returns the vault lookup path for the template's primary credential.
//
// Uses the canonical four-segment path format
// "default/<category>/<provider>/<field>" (e.g. "default/ai/openrouter/api_key").
// No backward-compat read from "default/connections/..." — v1.0.0 has no existing users.
// Falls back to an empty string when the template has no injection rules.
func vaultSecretRef(tmpl registry.ConnectionTemplate) string {
	if len(tmpl.InjectionRules) == 0 {
		return ""
	}
	category := tmpl.Category
	if category == "" {
		category = "ai" // safe default for provider templates that predate the category field
	}
	return "default/" + category + "/" + tmpl.Provider + "/" + tmpl.InjectionRules[0].Source
}
