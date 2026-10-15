package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/presence"
)

// requirePresence asks a human to approve action and records the outcome. A
// refusal is a security block (exit 2) whose message never names a way around
// it: its reader may be the agent the check exists to stop.
func requirePresence(ctx context.Context, action presence.Action, format string, args ...any) (presence.Proof, error) {
	proof, err := presence.Require(ctx, action, fmt.Sprintf(format, args...))
	recordPresenceDecision(ctx, action, proof, err)
	if err == nil {
		return proof, nil
	}
	switch {
	case errors.Is(err, presence.ErrNoTTY):
		return presence.Proof{}, NewSecurityBlock("%s needs a human at an interactive terminal. Run it yourself in a terminal; it cannot be scripted, piped or run by an agent.", action)
	case errors.Is(err, presence.ErrAgentTerminal):
		return presence.Proof{}, NewSecurityBlock("%s needs a human; this terminal belongs to an agent session.", action)
	case errors.Is(err, presence.ErrDenied):
		return presence.Proof{}, NewSecurityBlock("%s was not approved.", action)
	}
	return presence.Proof{}, NewSecurityBlock("%s could not be approved: %v", action, err)
}

// requirePolicyChange is requirePresence for an edit to policy or grants. A
// refused attempt is recorded as a refused policy.change; the caller records
// the applied one with recordPolicyChange.
func requirePolicyChange(ctx context.Context, action presence.Action, change, connection, format string, args ...any) (presence.Proof, error) {
	proof, err := requirePresence(ctx, action, format, args...)
	if err != nil {
		recordPolicyChange(ctx, audit.OutcomeDenied, change, connection, "", "not approved")
	}
	return proof, err
}
