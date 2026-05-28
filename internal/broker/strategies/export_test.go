// export_test.go exposes internal constructors for white-box testing with
// injectable HTTP endpoints. Not available in production builds.
package strategies

import (
	"crypto/rsa"
	"net/http"
	"time"
)

// NewGitHubAppInstallationStrategyWithURL creates a GitHubAppInstallationStrategy
// with a custom endpoint URL pattern for testing. urlPattern must be a
// fmt.Sprintf-compatible string with one %s placeholder for the installation ID.
func NewGitHubAppInstallationStrategyWithURL(appID, installationID string, key *rsa.PrivateKey, urlPattern string) *GitHubAppInstallationStrategy {
	s := NewGitHubAppInstallationStrategy(appID, installationID, key)
	s.endpointFmt = urlPattern
	return s
}

// NewAWSStsStrategyWithEndpoint creates an AWSStsStrategy pointing at a custom
// STS endpoint URL for testing (e.g., an httptest.Server).
func NewAWSStsStrategyWithEndpoint(
	roleARN, region string,
	getBaseCredentials func(string) (string, string, error),
	endpoint string,
) *AWSStsStrategy {
	s := NewAWSStsStrategy(roleARN, region, getBaseCredentials)
	s.stsEndpoint = endpoint
	s.httpClient = &http.Client{Timeout: 5 * time.Second}
	return s
}
