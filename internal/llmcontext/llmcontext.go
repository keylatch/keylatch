// Package llmcontext detects whether the current process is running inside an
// LLM-driven session. It is a leaf package — it imports only stdlib.
// S0-7: no imports from github.com/keylatch/keylatch/internal/*.
package llmcontext

import "os"

// Lookup resolves an environment variable name to its value.
type Lookup func(string) string

// DefaultLookup resolves from the process environment.
var DefaultLookup Lookup = func(k string) string { return os.Getenv(k) }

// IsLLMSession returns true if the current process is running inside an LLM-driven session.
//
// Detection runs in three priority tiers (EPIC-05):
//
//  1. KEYLATCH_LLM_TICKET env var — if set and non-empty, a signed session
//     ticket has been issued by keylatchd. Its presence alone is sufficient
//     to return true (fail-closed: the full cryptographic verification is
//     performed by VerifyTicket; the env signal is the fast-path gate).
//
//  2. keylatchd IPC query — if KEYLATCH_DAEMON_SOCKET is set, the daemon is
//     asked whether the current PID is an active LLM session. Any network
//     error, timeout, or schema mismatch causes this tier to fail closed
//     (returns true — assume LLM session).  A clean "active: false" from
//     the daemon is the only path to returning false from this tier.
//
//  3. Environment-variable signals (S0–S6) — the original seven signals
//     (CLAUDE_CODE, CODEX_ENV, etc.) checked in declaration order.
//
// Fail-closed contract: ambiguous or error states always return true.
// The only way IsLLMSession returns false is when ALL of the following hold:
//   - KEYLATCH_LLM_TICKET is absent or empty
//   - keylatchd IPC is either not configured or cleanly reports active=false
//   - no env-var signal fires
//
// S0-3: CREDENTIALS_LLM_SESSION=0 is the only explicit false value for the
// generic manual flag. Other non-empty values are treated as active sessions.
func IsLLMSession(env Lookup) bool {
	// Priority 1: signed session ticket.
	// A non-empty KEYLATCH_LLM_TICKET means a keylatchd-issued ticket is present.
	// Its presence is sufficient to return true (fail-closed on the fast path).
	// Full cryptographic verification (VerifyTicket) is the caller's concern when
	// they need to TRUST the ticket, not when they want to BLOCK on it.
	if env("KEYLATCH_LLM_TICKET") != "" {
		return true
	}

	// Priority 2: keylatchd IPC query.
	// Ask the daemon if the current PID is registered as an LLM session.
	// Only runs when KEYLATCH_DAEMON_SOCKET is set (daemon is available).
	if socketPath := env(daemonSocketEnvKey); socketPath != "" {
		active, err := queryDaemonLLMSession(socketPath, currentPID())
		if err != nil {
			// Fail closed: network/parse error → assume LLM session.
			return true
		}
		if active {
			return true
		}
		// Daemon explicitly says not active — fall through to env-var signals.
		// This allows env-var signals to still fire even if daemon says "not active".
	}

	// Priority 3: environment-variable signals (original behaviour, S0–S6).
	for _, sig := range Signals {
		if matches(sig, env(sig.EnvKey)) {
			return true
		}
	}
	return false
}

func matches(sig Signal, value string) bool {
	switch sig.MatchRule {
	case "non-empty":
		return value != ""
	case "llm-session":
		return value != "" && value != "0"
	case "equals:1":
		// Retained for forward compatibility: other "equals:<value>" rules may be
		// introduced for future signals. Do not remove this branch.
		return value == "1"
	default:
		return false
	}
}
