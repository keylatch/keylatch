package strategies

import (
	"github.com/keylatch/keylatch/internal/broker"
)

const googleTokenEndpoint = "https://oauth2.googleapis.com/token" //nolint:gosec // G101 false positive: this is an OAuth endpoint URL, not a credential

// GoogleOAuthStrategy extends OAuthRefreshStrategy for Google OAuth.
type GoogleOAuthStrategy struct {
	*OAuthRefreshStrategy
}

// NewGoogleOAuthStrategy creates a strategy for Google OAuth token refresh.
func NewGoogleOAuthStrategy(
	clientID, clientSecret string,
	getRefreshToken func(actor, namespace string) ([]byte, error),
) *GoogleOAuthStrategy {
	return &GoogleOAuthStrategy{
		OAuthRefreshStrategy: NewOAuthRefreshStrategy(
			"google",
			googleTokenEndpoint,
			clientID,
			clientSecret,
			getRefreshToken,
		),
	}
}

// Provider returns "google".
func (s *GoogleOAuthStrategy) Provider() string { return "google" }

// Ensure GoogleOAuthStrategy implements broker.ExchangeStrategy.
var _ broker.ExchangeStrategy = (*GoogleOAuthStrategy)(nil)
