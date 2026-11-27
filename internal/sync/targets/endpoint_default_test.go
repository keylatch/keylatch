//go:build !sync_test_endpoint

package targets

import "testing"

func TestDefaultBuildIgnoresEndpointVariables(t *testing.T) {
	t.Setenv("KEYLATCH_TEST_VERCEL_API_URL", "http://127.0.0.1:9")
	t.Setenv("KEYLATCH_TEST_GITHUB_API_URL", "http://127.0.0.1:10")
	if apiBase("vercel", vercelDefaultBase) != vercelDefaultBase || apiBase("github", githubDefaultBase) != githubDefaultBase {
		t.Fatal("the default build honors an endpoint variable")
	}
}
