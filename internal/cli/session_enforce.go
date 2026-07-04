package cli

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// session_enforce.go — M2: default signed-ticket enforcement (fail closed).
//
// Problem: IsLLMSession's legacy env-var heuristic (S0-S6, e.g. CLAUDE_CODE=1)
// is entirely within the classified process's own control. It is spoofable
// in both directions: an actual LLM agent could unset every known signal to
// look like a human terminal, or an unrelated script could set CLAUDE_CODE=1
// to look like an agent. Historically, `keylatch get`/`keylatch run` trusted
// this heuristic alone whenever no stronger signal (a signed ticket, or a
// keylatchd IPC verdict) was present.
//
// Fix: when llmcontext.ClassifySession(env) reports SignalHeuristic — i.e.
// the ONLY reason a session looks like an LLM session is the spoofable
// heuristic, with no ticket and no daemon corroboration either way — value-
// bearing commands (get, run) now refuse to proceed by default UNLESS
// keylatchd itself is reachable (daemonUp() == true), in which case the
// existing per-command guards (GuardLLMSession / GuardRuntime) remain the
// authority, exactly as before.
//
// Human sessions (ClassifySession == SignalNone) are never affected — this
// function is a no-op for them. Sessions verified via ticket or daemon IPC
// (SignalTicket / SignalDaemonActive / SignalDaemonError) are also left
// untouched here: those are already handled by the existing IsLLMSession-based
// guards, which will legitimately mask/block them because IsLLMSession==true.
//
// Escape hatch: KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 (llmcontext.EnvAllowUnverifiedSession)
// restores the pre-M2 behavior unconditionally.
const requireVerifiedSessionHint = "Start keylatchd (`keylatch ui` or `keylatch gateway up`) so sessions can be verified, or set KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 to restore the previous heuristic-only behavior."

// RequireVerifiedSession enforces M2 for value-bearing command entry points
// (get, run). Returns a non-nil error with actionable guidance when the
// command must fail closed; returns nil when it is safe to proceed to the
// command's existing (IsLLMSession-based) guards.
//
// daemonUp is injected for testability; production callers pass
// daemon.IsRunning. A nil daemonUp is treated as "keylatchd is not reachable"
// (fail closed) — production call sites MUST always pass a real function.
func RequireVerifiedSession(env llmcontext.Lookup, daemonUp func() bool) error {
	if env(llmcontext.EnvAllowUnverifiedSession) == "1" {
		return nil // explicit operator escape hatch — restores old behavior
	}

	if llmcontext.ClassifySession(env) != llmcontext.SignalHeuristic {
		// Either not an LLM session at all (human, unaffected), or the
		// verdict is already corroborated by a ticket or keylatchd IPC —
		// the existing guards handle those cases correctly.
		return nil
	}

	if daemonUp != nil && daemonUp() {
		// keylatchd is reachable — treat as before, downstream guards decide.
		return nil
	}

	return fmt.Errorf(
		"keylatch: LLM session detected via unverified environment signals only "+
			"(no signed session ticket, keylatchd unreachable) — refusing to proceed "+
			"(fail closed). %s", requireVerifiedSessionHint)
}
