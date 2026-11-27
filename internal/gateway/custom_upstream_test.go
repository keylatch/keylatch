package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomUpstreamURLTakesHostFromTheRuleOnly(t *testing.T) {
	rule := &registry.CustomEndpoint{Hosts: []string{"api.acme.example", "eu.acme.example"}}
	build := func(host, path, query string) (string, error) {
		return customUpstreamURL(&route.Route{Custom: rule, UpstreamHost: host, UpstreamPath: path}, query)
	}

	got, err := build("eu.acme.example", "/v1/a b", "x=1")
	require.NoError(t, err)
	assert.Equal(t, "https://eu.acme.example/v1/a%20b?x=1", got)

	for _, host := range []string{"evil.example", "api.acme.example:8443", "user@api.acme.example", "API.ACME.EXAMPLE", "api.acme.example.", ""} {
		_, err := build(host, "/v1", "")
		assert.Error(t, err, "host %q", host)
	}
	for _, p := range []string{"", "v1", "//evil.example/v1", "/v1/../x", "/v1/./x", `/v1\x`, "/v1/\n", "/v1/\x7f"} {
		_, err := build("api.acme.example", p, "")
		assert.Error(t, err, "path %q", p)
	}
	// Characters that would end the path or start userinfo stay inside the path.
	got, err = build("api.acme.example", "/v1/@evil.example/x?y#z", "")
	require.NoError(t, err)
	assert.Equal(t, "https://api.acme.example/v1/@evil.example/x%3Fy%23z", got)
	got, err = build("api.acme.example", "/v1/%2f%2fevil.example", "")
	require.NoError(t, err)
	assert.Equal(t, "https://api.acme.example/v1/%252f%252fevil.example", got)
}

func TestCustomSecret_RequestCannotSteerTheUpstreamHost(t *testing.T) {
	cases := []struct {
		name, target, host string
		headers            map[string]string
	}{
		{name: "host header", target: "/sdk/acme/v1/v1/models", host: "evil.example"},
		{name: "forwarded host header", target: "/sdk/acme/v1/v1/models", headers: map[string]string{"X-Forwarded-Host": "evil.example", "X-Original-URL": "https://evil.example/"}},
		{name: "absolute-form URL", target: "https://evil.example/sdk/acme/v1/v1/models"},
		{name: "absolute-form URL with the rule host", target: "https://evil.example@api.acme.example/sdk/acme/v1/v1/models"},
		{name: "double slash path", target: "/sdk/acme/v1//evil.example/v1"},
		{name: "double slash after the prefix", target: "/sdk/acme/v1/v1//evil.example/x"},
		{name: "userinfo in the path", target: "/sdk/acme/v1/v1/@evil.example/x"},
		{name: "userinfo in the host segment", target: "/sdk/acme/h/api.acme.example@evil.example/v1/x"},
		{name: "encoded slash", target: "/sdk/acme/v1/v1%2f%2fevil.example/x"},
		{name: "encoded dot segments", target: "/sdk/acme/v1/v1/%2e%2e/%2e%2e/x"},
		{name: "encoded at sign", target: "/sdk/acme/v1/%40evil.example"},
		{name: "encoded backslash", target: "/sdk/acme/v1/v1/%5c%5cevil.example"},
		{name: "encoded host segment", target: "/sdk/acme/h/api%2eacme%2eexample%40evil.example/v1"},
		{name: "unlisted host segment", target: "/sdk/acme/h/evil.example/v1/x"},
		{name: "port in the host segment", target: "/sdk/acme/h/api.acme.example:8443/v1/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := customHarness(t, nil)
			jwtStr := h.customToken(t, nil)
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			req.Header.Set("Authorization", "Bearer "+jwtStr)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			h.do(t, req)
			for _, up := range h.upstream {
				assert.Contains(t, []string{"api.acme.example", "eu.acme.example"}, up.URL.Host, "only a rule host is ever contacted")
				assert.Equal(t, "https", up.URL.Scheme)
				assert.Nil(t, up.URL.User)
				assert.False(t, strings.HasPrefix(up.URL.Path, "//"))
			}
		})
	}
}
