//go:build !mint_test_endpoint

package strategies

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultBuildIgnoresEndpointOverride(t *testing.T) {
	t.Setenv("KEYLATCH_TEST_GITHUB_API_URL", "http://127.0.0.1:9")

	s := NewGitHubAppInstallationStrategy("1", "2", nil)
	assert.Equal(t, DefaultGitHubAPIBase, s.apiBase)

	s = NewGitHubAppInstallationStrategy("1", "2", nil, WithGitHubAPIBase("https://ghe.example.com/api/v3"))
	assert.Equal(t, "https://ghe.example.com/api/v3", s.apiBase, "an explicit base is the only way to change it")
}
