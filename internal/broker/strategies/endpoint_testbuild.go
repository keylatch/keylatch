//go:build mint_test_endpoint

package strategies

import (
	"os"
	"strings"
)

// apiBaseOverride reads the GitHub API root from KEYLATCH_TEST_GITHUB_API_URL.
// Only the conformance test build (tag mint_test_endpoint) has this; it exists
// so a mint can be run against a stub GitHub server, and its `keylatch version`
// says testendpoint.
func apiBaseOverride() string {
	return strings.TrimRight(os.Getenv("KEYLATCH_TEST_GITHUB_API_URL"), "/")
}
