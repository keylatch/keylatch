// export_test.go exposes internal constructors for white-box testing with
// injectable HTTP endpoints. Not available in production builds.
package strategies

import (
	"crypto/rsa"
	"time"
)

// NewGitHubAppInstallationStrategyWithAPI creates a GitHubAppInstallationStrategy
// that talks to apiBase (e.g. an httptest.Server URL) with a fixed clock.
func NewGitHubAppInstallationStrategyWithAPI(appID, installationID string, key *rsa.PrivateKey, apiBase string, now func() time.Time) *GitHubAppInstallationStrategy {
	s := NewGitHubAppInstallationStrategy(appID, installationID, key, WithGitHubAPIBase(apiBase))
	if now != nil {
		s.now = now
	}
	return s
}
