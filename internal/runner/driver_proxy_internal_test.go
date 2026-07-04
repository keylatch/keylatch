package runner

// driver_proxy_internal_test.go — white-box tests for isCredentialShapedName,
// the docker-server-security pattern-matching denylist added on top of
// providerKeyDenylist in driver_proxy.go. Uses package runner (not
// runner_test) because isCredentialShapedName is unexported.

import "testing"

func TestIsCredentialShapedName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Exact-name denylist (pre-existing).
		{"OPENAI_API_KEY", true},
		{"ANTHROPIC_API_KEY", true},

		// Pattern-matched: not on the exact-name list, but credential-shaped.
		{"AWS_SECRET_ACCESS_KEY", true},
		{"AWS_SESSION_TOKEN", true},
		{"NPM_TOKEN", true},
		{"VERCEL_TOKEN", true},
		{"DATABASE_URL_SECRET", true},
		{"MY_CUSTOM_SECRET", true},
		{"SOME_APP_PASSWORD", true},
		{"LEGACY_APP_PASSWD", true},
		{"SERVICE_CREDENTIAL", true},
		{"SERVICE_CREDENTIALS", true},
		{"TLS_PRIVATE_KEY", true},
		{"lowercase_api_key", true}, // matching is case-insensitive

		// Benign — must pass through.
		{"PATH", false},
		{"LANG", false},
		{"NODE_ENV", false},
		{"MY_APP_REGION", false},
	}
	for _, tc := range cases {
		got := isCredentialShapedName(tc.name)
		if got != tc.want {
			t.Errorf("isCredentialShapedName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
