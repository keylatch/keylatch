//go:build mint_test_endpoint

package strategies

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTestBuildHonorsEndpointOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TEST_GITHUB_API_URL", "http://127.0.0.1:9/")

	s := NewGitHubAppInstallationStrategy("1", "2", nil)
	assert.Equal(t, "http://127.0.0.1:9", s.apiBase)

	s = NewGitHubAppInstallationStrategy("1", "2", nil, WithGitHubAPIBase(DefaultGitHubAPIBase))
	assert.Equal(t, "http://127.0.0.1:9", s.apiBase, "the override wins over the base a caller passes")

	t.Setenv("KEYLATCH_TEST_GITHUB_API_URL", "")
	s = NewGitHubAppInstallationStrategy("1", "2", nil)
	assert.Equal(t, DefaultGitHubAPIBase, s.apiBase, "without the variable the test build talks to GitHub")
}
