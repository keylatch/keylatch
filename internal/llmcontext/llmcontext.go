// Package llmcontext detects whether the current process is running inside an
// LLM-driven session. It is a leaf package — it imports only stdlib.
// No imports from github.com/keylatch/keylatch/internal/*.
package llmcontext

import "os"

// Lookup resolves an environment variable name to its value.
type Lookup func(string) string

// DefaultLookup resolves from the process environment.
var DefaultLookup Lookup = func(k string) string { return os.Getenv(k) }

// EnvAllowUnverifiedSession is the explicit escape hatch for the
// raw-credential session gate (default signed-ticket enforcement,
// docker-server-security hardening pass).
//
// By default, `keylatch get`/`keylatch run` fail closed when a session is
// classified as SignalHeuristic (see ClassifySession) — i.e. the ONLY reason
// IsLLMSession returned true is the legacy env-var heuristic (S0-S6), which
// is entirely within the classified process's own control (an agent can
// unset it to look human; a script can set it to look like an agent) and is
// not corroborated by a signed ticket or a live keylatchd.
//
// Setting KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 restores the pre-gate behavior:
// the heuristic alone is trusted, matching the original IsLLMSession
// contract. llmcontext itself never fails closed on this — it only exposes
// the classification; internal/cli's session-enforcement helper is what
// consumes this env var to decide whether to refuse a command.
const EnvAllowUnverifiedSession = "KEYLATCH_ALLOW_UNVERIFIED_SESSION"

// SessionSignal classifies *how* IsLLMSession reached its verdict, so callers
// that need stronger assurance than a plain bool (the raw-credential session
// gate's default signed-ticket enforcement) can distinguish a
// verified/corroborated detection from a bare, spoofable heuristic match.
type SessionSignal int

const (
	// SignalNone: no tier detected an LLM session. IsLLMSession returns false.
	SignalNone SessionSignal = iota
	// SignalTicket: KEYLATCH_LLM_TICKET is present (Priority 1). Presence-only
	// fast path — see IsLLMSession's doc comment. Full cryptographic
	// verification is VerifyTicket, which requires keylatchd's in-memory
	// signing key and is not performed by this classification.
	SignalTicket
	// SignalDaemonActive: keylatchd IPC (KEYLATCH_DAEMON_SOCKET) explicitly
	// confirmed active=true for this PID (Priority 2).
	SignalDaemonActive
	// SignalDaemonError: keylatchd IPC was configured but the query failed
	// (network error, timeout, bad schema). IsLLMSession fails closed here
	// (treats as true) just like SignalDaemonActive, but this is NOT an
	// actual daemon-corroborated verdict — it is distinguished so callers
	// doing stronger verification (the raw-credential session gate) can tell the two apart.
	SignalDaemonError
	// SignalHeuristic: none of the above fired conclusively — IsLLMSession's
	// "true" verdict (if any) came entirely from the legacy env-var signals
	// (S0-S6). This is the only tier that is fully spoofable by the very
	// process being classified.
	SignalHeuristic
)

// ClassifySession runs the same three-tier detection IsLLMSession uses, but
// returns which tier produced the verdict instead of collapsing it to a
// bool. Invariant: IsLLMSession(env) == (ClassifySession(env) != SignalNone).
func ClassifySession(env Lookup) SessionSignal {
	// Priority 1: signed session ticket (presence-only fast path).
	if env("KEYLATCH_LLM_TICKET") != "" {
		return SignalTicket
	}

	// Priority 2: keylatchd IPC query.
	if socketPath := env(daemonSocketEnvKey); socketPath != "" {
		active, err := queryDaemonLLMSession(socketPath, currentPID())
		if err != nil {
			return SignalDaemonError
		}
		if active {
			return SignalDaemonActive
		}
		// Daemon explicitly said "not active" — fall through to env-var
		// signals, mirroring IsLLMSession.
	}

	// Priority 3: environment-variable signals (original behaviour, S0-S6).
	for _, sig := range Signals {
		if matches(sig, env(sig.EnvKey)) {
			return SignalHeuristic
		}
	}
	return SignalNone
}

// IsLLMSession returns true if the current process is running inside an LLM-driven session.
//
// Detection runs in three priority tiers:
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
// CREDENTIALS_LLM_SESSION=0 is the only explicit false value for the
// generic manual flag. Other non-empty values are treated as active sessions.
func IsLLMSession(env Lookup) bool {
	return ClassifySession(env) != SignalNone
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
