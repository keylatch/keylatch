package registry

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every core template lists the routes that create, read or list credentials
// or keys for its provider, and each of those routes is refused.
func TestCoreTemplatesDenyCredentialRoutes(t *testing.T) {
	cases := []struct {
		provider string
		denied   []string // "METHOD /path"
		allowed  []string
	}{
		{"cloudflare",
			[]string{"POST /client/v4/user/tokens", "GET /client/v4/user/tokens/", "PUT /client/v4/user/tokens/abc/value", "POST /client/v4/accounts/a1/tokens", "GET /client/v4/accounts/a1/access/service_tokens"},
			[]string{"GET /client/v4/user/tokens/verify", "GET /client/v4/zones"}},
		{"dropbox",
			[]string{"POST /oauth2/token", "POST /2/team/token/get_authenticated_admin"},
			[]string{"POST /2/users/get_current_account", "POST /2/files/list_folder"}},
		{"github-app",
			[]string{"POST /app/installations/42/access_tokens", "GET /user/keys", "POST /repos/o/r/keys", "GET /repos/o/r/actions/secrets/NAME", "POST /app-manifests/code/conversions"},
			[]string{"GET /app", "GET /repos/o/r/issues"}},
		{"google_workspace",
			[]string{"POST /token", "POST /v1/projects/p/serviceAccounts/sa@p.iam:generateAccessToken", "GET /v1/projects/p/serviceAccounts/sa/keys", "POST /v1/projects/p/serviceAccounts/sa/keys/k1"},
			[]string{"GET /oauth2/v3/userinfo", "GET /admin/directory/v1/users"}},
		{"openrouter",
			[]string{"GET /api/v1/keys", "POST /api/v1/keys", "DELETE /api/v1/keys/hash", "POST /api/v1/auth/keys"},
			[]string{"GET /api/v1/models", "POST /api/v1/chat/completions"}},
		{"sentry",
			[]string{"GET /api/0/api-tokens/", "POST /api/0/projects/org/proj/keys/", "GET /api/0/organizations/org/api-keys/", "GET /api/0/sentry-app-installations/uuid/authorizations/"},
			[]string{"GET /api/0/projects/", "GET /api/0/organizations/"}},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			tmpl, err := Get(tc.provider)
			require.NoError(t, err)
			assert.NotEmpty(t, tmpl.DenyRoutes, "%s must list its credential routes in deny_routes", tc.provider)
			require.NoError(t, ValidateDenyRoutes(tmpl))
			for _, r := range tc.denied {
				method, p, _ := strings.Cut(r, " ")
				assert.True(t, tmpl.DeniesRoute(method, p), "%s should be denied for %s", r, tc.provider)
			}
			for _, r := range tc.allowed {
				method, p, _ := strings.Cut(r, " ")
				assert.False(t, tmpl.DeniesRoute(method, p), "%s should be allowed for %s", r, tc.provider)
			}
		})
	}

	// A new core template cannot ship without a case here.
	files, err := filepath.Glob("../../templates/providers/core/*.yaml")
	require.NoError(t, err)
	assert.Len(t, files, len(cases), "every core template needs a case in this test")
}

const exposingTemplate = `
provider: leaky
display_name: Leaky
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/leaky/{{.Account}}"
trust_level: 0
runtime_support:
  preferred: gateway_typed
actions:
  %s:
    method: GET
    path: %s
%s
test_strategy:
  kind: http_get
  endpoint: https://api.example.com/v1
  expect:
    status_code: 200
`

func TestTemplateExposingKeyRouteFails(t *testing.T) {
	build := func(action, route, extra string) []byte {
		return []byte(fmt.Sprintf(exposingTemplate, action, route, extra))
	}

	err := ValidateTemplateBytes(build("list-keys", "/v1/api_keys", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential route")
	assert.Contains(t, err.Error(), "/v1/api_keys")

	// Naming the route in deny_routes does not make an exposed action valid:
	// the gateway would refuse it, so the action must go.
	err = ValidateTemplateBytes(build("list-keys", "/v1/api_keys", "deny_routes:\n  - /v1/api_keys"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deny_routes refuses")

	// An ordinary route passes, with or without unrelated deny entries.
	require.NoError(t, ValidateTemplateBytes(build("list-models", "/v1/models", "")))
	require.NoError(t, ValidateTemplateBytes(build("list-models", "/v1/models", "deny_routes:\n  - /v1/api_keys")))

	// Malformed entries are rejected by the schema.
	require.Error(t, ValidateTemplateBytes(build("list-models", "/v1/models", "deny_routes:\n  - v1/api_keys")))
}

func TestRouteDeniedMatching(t *testing.T) {
	entries := []string{"/a/*/keys", "POST /b/**", "/c/*:sign", "* /d"}
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/a/x/keys", true},
		{"GET", "/a/x/keys/", true},
		{"GET", "/A/X/KEYS", true},
		{"GET", "/a/x/keys/y", false},
		{"GET", "/a/keys", false},
		{"POST", "/b", true},
		{"POST", "/b/c/d", true},
		{"GET", "/b/c", false},
		{"GET", "/c/acct:sign", true},
		{"GET", "/c/acct", false},
		{"DELETE", "/d", true},
	} {
		assert.Equal(t, tc.want, RouteDenied(entries, tc.method, tc.path), "%s %s", tc.method, tc.path)
	}
	assert.False(t, RouteDenied(nil, "GET", "/anything"))
}
