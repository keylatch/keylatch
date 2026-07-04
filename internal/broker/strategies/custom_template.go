package strategies

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// forbiddenOutputFields is the set of field name patterns that a template must
// not return as plain output fields, per the security model.
var forbiddenOutputFields = []string{
	"token", "access_token", "key", "secret",
}

// CustomTemplateStrategy validates and executes a custom exchange template.
// It rejects templates that attempt to return provider tokens as plain output fields.
type CustomTemplateStrategy struct {
	provider     string
	outputFields []string // declared output field names from the template
	exchangeFunc func(ctx context.Context, actor, sessionID, namespace string) ([]byte, time.Duration, error)
}

// NewCustomTemplateStrategy creates the strategy.
// outputFields is the list of field names the template declares it will return.
// exchangeFunc is the function that performs the actual exchange.
// Returns an error if outputFields contains a forbidden field name.
func NewCustomTemplateStrategy(
	provider string,
	outputFields []string,
	exchangeFunc func(ctx context.Context, actor, sessionID, namespace string) ([]byte, time.Duration, error),
) (*CustomTemplateStrategy, error) {
	if err := validateOutputFields(outputFields); err != nil {
		return nil, err
	}
	return &CustomTemplateStrategy{
		provider:     provider,
		outputFields: outputFields,
		exchangeFunc: exchangeFunc,
	}, nil
}

// Provider returns the provider slug.
func (s *CustomTemplateStrategy) Provider() string { return s.provider }

// Exchange runs the custom template after re-validating output field constraints.
func (s *CustomTemplateStrategy) Exchange(ctx context.Context, actor, sessionID, namespace string) (broker.ExchangeResult, error) {
	if err := validateOutputFields(s.outputFields); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("custom_template: template validation failed: %w", err)
	}

	tokenBytes, ttl, err := s.exchangeFunc(ctx, actor, sessionID, namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("custom_template: exchange: %w", err)
	}

	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, tokenBytes)
	zeroBytes(tokenBytes)
	return result, nil
}

// validateOutputFields rejects templates that declare forbidden token field names.
func validateOutputFields(fields []string) error {
	for _, field := range fields {
		lower := strings.ToLower(strings.TrimSpace(field))
		for _, forbidden := range forbiddenOutputFields {
			if lower == forbidden {
				return fmt.Errorf("custom_template: output field %q is forbidden — templates must not return token values as plain fields", field)
			}
		}
	}
	return nil
}
