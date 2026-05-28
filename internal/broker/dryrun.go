package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

// ErrProviderNoBrokerConfig is returned when a provider has no broker
// configuration (e.g. no strategy registered for it).
var ErrProviderNoBrokerConfig = errors.New("broker: provider has no broker configuration")

// dryRunExchange simulates a token exchange for provider and command without
// calling the provider endpoint or mutating the cache.
//
// It:
//  1. Looks up the registered strategy for provider.
//  2. Derives scopes from the command string using simple prefix heuristics.
//  3. Runs a policy check (always "allow" in the current implementation;
//     future phases will consult the policy engine).
//  4. Emits a BrokerDryRunRequested audit event.
//  5. Returns a DryRunResult.
//
// Returns ErrProviderNoBrokerConfig if the provider has no registered strategy.
func dryRunExchange(b *BrokerImpl, provider, command string) (*DryRunResult, error) {
	if _, ok := b.strategies[provider]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNoBrokerConfig, provider)
	}

	scopes := deriveScopesFromCommand(provider, command)

	// Policy check — current implementation always allows.
	// Future phases will consult the policy engine.
	decision := "allow"
	reason := "no policy restrictions configured"

	// Emit audit event.
	if b.auditEmitter != nil {
		ev := audit.Event{
			Action:  ActionBrokerDryRunRequested,
			Outcome: audit.OutcomeOK,
			Extra: map[string]any{
				"provider":        provider,
				"command":         command,
				"scopes_count":    len(scopes),
				"policy_decision": decision,
			},
		}
		_ = b.auditEmitter.Emit(context.Background(), ev)
	}

	return &DryRunResult{
		Provider:        provider,
		ScopesRequested: scopes,
		ScopedTokenTTL:  time.Hour, // default TTL; provider templates will refine in future phases
		PolicyDecision:  decision,
		Reason:          reason,
	}, nil
}

// deriveScopesFromCommand derives a list of scopes that a command would
// request from a provider. The heuristic is intentionally simple:
//
//   - If the command is empty, return a single wildcard scope.
//   - Otherwise, convert the command's first word to a provider-prefixed scope
//     (e.g. "openrouter" + "chat" → "openrouter.chat").
func deriveScopesFromCommand(provider, command string) []string {
	if command == "" {
		return []string{provider + ".*"}
	}
	// Take the first word (binary name or sub-command) as the scope action.
	parts := strings.Fields(command)
	action := parts[0]
	// Strip any path prefix.
	if idx := strings.LastIndexAny(action, "/\\"); idx >= 0 {
		action = action[idx+1:]
	}
	// Normalise: lowercase, strip extension.
	action = strings.ToLower(action)
	action = strings.TrimSuffix(action, ".exe")
	action = strings.TrimSuffix(action, ".sh")

	return []string{fmt.Sprintf("%s.%s", provider, action)}
}

// Audit event action names for dry-run operations.
const (
	// ActionBrokerDryRunRequested is emitted when a dry-run exchange is requested.
	ActionBrokerDryRunRequested = "broker.dry_run_requested"
)
