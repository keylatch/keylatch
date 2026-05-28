package strategies

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// StaticGatewayOnlyStrategy loads a static API token into memory.
// Returns ErrUnsupportedExchange if called from a direct_brokered context
// (detected via the namespace convention "direct_brokered:*").
type StaticGatewayOnlyStrategy struct {
	provider string
	getToken func(namespace string) ([]byte, error)
}

// NewStaticGatewayOnlyStrategy creates the strategy.
// getToken retrieves the static token for a given namespace.
func NewStaticGatewayOnlyStrategy(provider string, getToken func(namespace string) ([]byte, error)) *StaticGatewayOnlyStrategy {
	return &StaticGatewayOnlyStrategy{
		provider: provider,
		getToken: getToken,
	}
}

// Provider returns the provider slug.
func (s *StaticGatewayOnlyStrategy) Provider() string { return s.provider }

// Exchange returns the static token. Returns ErrUnsupportedExchange if the
// namespace signals a direct_brokered context.
func (s *StaticGatewayOnlyStrategy) Exchange(_ context.Context, _, _, namespace string) (broker.ExchangeResult, error) {
	// Gate: static tokens are not available in direct_brokered mode (N-1).
	if strings.HasPrefix(namespace, "direct_brokered:") {
		return broker.ExchangeResult{}, broker.ErrUnsupportedExchange
	}

	token, err := s.getToken(namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("static_gateway: get token: %w", err)
	}

	// Static tokens have max TTL.
	ttl := time.Duration(math.MaxInt64)
	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, token)
	zeroBytes(token)
	return result, nil
}
