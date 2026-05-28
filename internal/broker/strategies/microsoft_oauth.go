package strategies

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/broker"
)

// MicrosoftOAuthStrategy extends OAuthRefreshStrategy for Microsoft OAuth.
// It supports both tenant-specific and common endpoints.
type MicrosoftOAuthStrategy struct {
	*OAuthRefreshStrategy
}

// NewMicrosoftOAuthStrategy creates a strategy for Microsoft OAuth token refresh.
// Pass tenantID as "common" for multi-tenant applications.
func NewMicrosoftOAuthStrategy(
	tenantID, clientID, clientSecret string,
	getRefreshToken func(actor, namespace string) ([]byte, error),
) *MicrosoftOAuthStrategy {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	return &MicrosoftOAuthStrategy{
		OAuthRefreshStrategy: NewOAuthRefreshStrategy(
			"microsoft",
			endpoint,
			clientID,
			clientSecret,
			getRefreshToken,
		),
	}
}

// Provider returns "microsoft".
func (s *MicrosoftOAuthStrategy) Provider() string { return "microsoft" }

// Ensure MicrosoftOAuthStrategy implements broker.ExchangeStrategy.
var _ broker.ExchangeStrategy = (*MicrosoftOAuthStrategy)(nil)
