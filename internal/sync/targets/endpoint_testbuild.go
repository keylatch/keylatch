//go:build sync_test_endpoint

package targets

import (
	"os"
	"strings"
)

// apiBase reads the API root from KEYLATCH_TEST_VERCEL_API_URL or
// KEYLATCH_TEST_GITHUB_API_URL. Only the conformance test build (tag
// sync_test_endpoint) has this, so a sync can run against stub servers; its
// `keylatch version` says testendpoint.
func apiBase(service, def string) string {
	name := map[string]string{"vercel": "KEYLATCH_TEST_VERCEL_API_URL", "github": "KEYLATCH_TEST_GITHUB_API_URL"}[service]
	if v := strings.TrimRight(os.Getenv(name), "/"); name != "" && v != "" {
		return v
	}
	return def
}
