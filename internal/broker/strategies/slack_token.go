package strategies

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// SlackTokenStrategy loads a Slack bot/user token from the keyring backend.
// Token is stored in memory only — never on disk.
type SlackTokenStrategy struct {
	provider string
	// getToken retrieves the token from the OS keyring for the given actor/namespace.
	getToken func(actor, namespace string) ([]byte, error)
}

// NewSlackTokenStrategy creates the strategy.
func NewSlackTokenStrategy(getToken func(actor, namespace string) ([]byte, error)) *SlackTokenStrategy {
	return &SlackTokenStrategy{
		provider: "slack",
		getToken: getToken,
	}
}

// Provider returns "slack".
func (s *SlackTokenStrategy) Provider() string { return s.provider }

// Exchange retrieves the Slack token from the keyring.
// Token bytes are stored in memory only and never serialised.
func (s *SlackTokenStrategy) Exchange(_ context.Context, actor, _, namespace string) (broker.ExchangeResult, error) {
	token, err := s.getToken(actor, namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("slack_token: get from keyring: %w", err)
	}

	if len(token) == 0 {
		return broker.ExchangeResult{}, fmt.Errorf("slack_token: empty token from keyring")
	}

	// Slack tokens are long-lived; use max TTL.
	ttl := time.Duration(math.MaxInt64)
	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, token)
	zeroBytes(token)
	return result, nil
}
