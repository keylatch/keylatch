package route

import (
	"net/http"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func customTemplate(paths, methods []string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider:       "acme",
		Category:       "custom",
		TrustLevel:     registry.TrustLocalOnly,
		AuthPlacement:  registry.AuthPlacement{In: "header", Name: "X-Api-Key", Format: "{value}"},
		RuntimeSupport: registry.RuntimeSupport{Preferred: registry.RuntimeGatewaySDK, Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK}},
		InjectionRules: []registry.InjectionRule{{Source: "value"}},
		Custom:         &registry.CustomEndpoint{Hosts: []string{"api.acme.example", "eu.acme.example"}, Paths: paths, Methods: methods},
	}
}

func TestCustomRouteMatching(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/v1", "/health"}, []string{"GET", "POST"})})
	require.NoError(t, err)

	allowed := []struct{ method, in, upstream string }{
		{"GET", "/sdk/acme/v1/v1", "/v1"},
		{"POST", "/sdk/acme/v1/v1/chat/completions", "/v1/chat/completions"},
		{"GET", "/sdk/acme/v1/health", "/health"},
		{"GET", "/sdk/acme/v1/v1/", "/v1/"},
	}
	for _, tc := range allowed {
		rt, ok := r.Match(tc.method, tc.in)
		require.True(t, ok, "%s %s", tc.method, tc.in)
		assert.Equal(t, "acme", rt.Provider)
		assert.Equal(t, "acme.request", rt.Capability)
		assert.Equal(t, "api.acme.example", rt.UpstreamHost, "requests go to the first host only")
		assert.Equal(t, tc.upstream, rt.UpstreamPath)
		assert.Equal(t, tc.method, rt.Method)
		assert.False(t, rt.LLMSessionDeny, "LLM sessions may use custom secrets within their rules")
		assert.Equal(t, "default/custom/acme/value", rt.SecretRef)
		assert.Equal(t, "X-Api-Key", rt.AuthPlacement.Name)
	}

	denied := []struct{ method, in, why string }{
		{"DELETE", "/sdk/acme/v1/v1/x", "method not allowed"},
		{"PUT", "/sdk/acme/v1/health", "method not allowed"},
		{"GET", "/sdk/acme/v1/admin", "path outside every prefix"},
		{"GET", "/sdk/acme/v1/", "root is not an allowed prefix"},
		{"GET", "/sdk/acme/v1/v1beta/x", "prefix must end on a segment boundary"},
		{"GET", "/sdk/acme/v1/v10", "prefix must end on a segment boundary"},
		{"GET", "/sdk/acme/v1/v1/../admin", "dot-dot segment"},
		{"GET", "/sdk/acme/v1/v1/./x", "dot segment"},
		{"GET", "/sdk/acme/v1/v1//x", "empty segment"},
		{"GET", "/sdk/acme/v1//evil.example/v1", "authority-looking path"},
		{"GET", "/sdk/acme/v1", "missing /v1/ marker"},
		{"GET", "/sdk/acme/v2/v1", "wrong version marker"},
		{"GET", "/sdk/other/v1/v1", "unknown secret"},
		{"GET", "/sdk/acme/extra/v1/v1", "name must be the single segment before /v1/"},
		{"GET", "/api/acme/request", "not an action route"},
	}
	for _, tc := range denied {
		_, ok := r.Match(tc.method, tc.in)
		assert.False(t, ok, "%s %s (%s)", tc.method, tc.in, tc.why)
	}
}

func TestCustomRouteAnyMethodAndRootPrefix(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/"}, nil)})
	require.NoError(t, err)

	for _, m := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		rt, ok := r.Match(m, "/sdk/acme/v1/any/path")
		require.True(t, ok, m)
		assert.Equal(t, "/any/path", rt.UpstreamPath)
	}
	_, ok := r.Match(http.MethodGet, "/sdk/acme/v1/a/../b")
	assert.False(t, ok)
}

func TestCustomRouteIsPerRequestCopy(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/"}, nil)})
	require.NoError(t, err)

	first, ok := r.Match("GET", "/sdk/acme/v1/one")
	require.True(t, ok)
	second, ok := r.Match("POST", "/sdk/acme/v1/two")
	require.True(t, ok)
	assert.Equal(t, "/one", first.UpstreamPath, "a later match must not rewrite an earlier route")
	assert.Equal(t, "GET", first.Method)
	assert.Equal(t, "/two", second.UpstreamPath)
}

func TestCustomRouteListedAndDoesNotShadowTemplates(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/"}, nil)})
	require.NoError(t, err)
	routes := r.Routes()
	require.Len(t, routes, 1)
	assert.Equal(t, "acme", routes[0].Provider)
}

func TestCustomRouteDefaultMethodsExcludeTraceAndConnect(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/"}, nil)})
	require.NoError(t, err)
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		_, ok := r.Match(m, "/sdk/acme/v1/x")
		assert.True(t, ok, m)
	}
	for _, m := range []string{"TRACE", "CONNECT", "PROPFIND", ""} {
		_, ok := r.Match(m, "/sdk/acme/v1/x")
		assert.False(t, ok, "%q", m)
	}

	// Even listed explicitly, TRACE and CONNECT stay refused.
	r, err = Compile([]registry.ConnectionTemplate{customTemplate([]string{"/"}, []string{"GET", "TRACE", "CONNECT"})})
	require.NoError(t, err)
	_, ok := r.Match("GET", "/sdk/acme/v1/x")
	assert.True(t, ok)
	for _, m := range []string{"TRACE", "CONNECT"} {
		_, ok = r.Match(m, "/sdk/acme/v1/x")
		assert.False(t, ok, m)
	}
}

func TestCustomRouteRefusesEncodedAndNonCanonicalPathsAtTheRouter(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/v1"}, nil)})
	require.NoError(t, err)
	// r.Match sees the decoded path, so %2e%2e and %2f arrive as these forms.
	for _, p := range []string{
		"/sdk/acme/v1/v1/../admin", "/sdk/acme/v1/v1/./x", "/sdk/acme/v1//evil.example/v1",
		"/sdk/acme/v1/v1//x", "/sdk/acme/v1/v1/x/..", "/sdk/acme/v1/v1/..",
	} {
		_, ok := r.Match("GET", p)
		assert.False(t, ok, p)
	}
}

func TestCustomRouteSecondHostAndHostSegmentRefusals(t *testing.T) {
	r, err := Compile([]registry.ConnectionTemplate{customTemplate([]string{"/v1"}, []string{"GET"})})
	require.NoError(t, err)

	rt, ok := r.Match("GET", "/sdk/acme/h/eu.acme.example/v1/models")
	require.True(t, ok)
	assert.Equal(t, "eu.acme.example", rt.UpstreamHost)
	assert.Equal(t, "/v1/models", rt.UpstreamPath)
	rt, ok = r.Match("GET", "/sdk/acme/h/api.acme.example/v1")
	require.True(t, ok, "the first host is also reachable by name")
	assert.Equal(t, "api.acme.example", rt.UpstreamHost)
	rt, _ = r.Match("GET", "/sdk/acme/v1/v1/x")
	assert.Equal(t, "api.acme.example", rt.UpstreamHost, "/v1/ still goes to the first host")

	// Paths and methods apply to every host.
	_, ok = r.Match("GET", "/sdk/acme/h/eu.acme.example/admin")
	assert.False(t, ok)
	_, ok = r.Match("POST", "/sdk/acme/h/eu.acme.example/v1/x")
	assert.False(t, ok)

	for _, p := range []string{
		"/sdk/acme/h/evil.example/v1/x",
		"/sdk/acme/h/EU.acme.example/v1/x",
		"/sdk/acme/h/eu.acme.example./v1/x",
		"/sdk/acme/h/eu.acme.example:443/v1/x",
		"/sdk/acme/h/user@eu.acme.example/v1/x",
		"/sdk/acme/h/eu.acme.example@evil.example/v1/x",
		"/sdk/acme/h/evil.example@eu.acme.example/v1/x",
		"/sdk/acme/h/eu.acme.example%2Fevil/v1/x",
		"/sdk/acme/h/eu.acme.example/../evil.example/v1/x",
		"/sdk/acme/h/eu.acme.example\\@evil.example/v1/x",
		"/sdk/acme/h/127.0.0.1/v1/x",
		"/sdk/acme/h/2130706433/v1/x",
		"/sdk/acme/h/[::1]/v1/x",
		"/sdk/acme/h//v1/x",
		"/sdk/acme/h/eu.acme.example",
		"/sdk/acme/h/",
		"/sdk/acme/h",
		"/sdk/acme/h/*.acme.example/v1/x",
		"/sdk/acme/h/eu.acme.example//evil.example/v1",
	} {
		_, ok := r.Match("GET", p)
		assert.False(t, ok, p)
	}
}

func TestListedHostReturnsOnlyConfiguredEntries(t *testing.T) {
	hosts := []string{"api.acme.example", "eu.acme.example"}
	got, ok := listedHost(hosts, "eu.acme.example")
	assert.True(t, ok)
	assert.Equal(t, "eu.acme.example", got)
	for _, h := range []string{"", "evil.example", "EU.acme.example", "eu.acme.example."} {
		got, ok = listedHost(hosts, h)
		assert.False(t, ok, "host %q", h)
		assert.Empty(t, got)
	}
}
