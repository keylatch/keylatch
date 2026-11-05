//go:build sync_test_endpoint

package targets

import "testing"

func TestSyncTestBuildHonorsEndpointOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TEST_VERCEL_API_URL", "http://127.0.0.1:9/")
	t.Setenv("KEYLATCH_TEST_GITHUB_API_URL", "http://127.0.0.1:10")
	if got := apiBase("vercel", vercelDefaultBase); got != "http://127.0.0.1:9" {
		t.Fatalf("vercel base = %q", got)
	}
	if got := apiBase("github", githubDefaultBase); got != "http://127.0.0.1:10" {
		t.Fatalf("github base = %q", got)
	}
	t.Setenv("KEYLATCH_TEST_VERCEL_API_URL", "")
	if got := apiBase("vercel", vercelDefaultBase); got != vercelDefaultBase {
		t.Fatalf("without the variable the test build talks to Vercel, got %q", got)
	}
	if got := apiBase("other", "x"); got != "x" {
		t.Fatalf("unknown service base = %q", got)
	}
}
