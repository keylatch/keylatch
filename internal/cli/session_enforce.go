package cli

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// session_enforce.go — raw-credential session gate: raw-credential-path corroboration (fail closed).
//
// Problem: a naive "gate every LLM-heuristic session" rule (the original
// shape) only refused when llmcontext.ClassifySession(env) reported
// SignalHeuristic — i.e. the ONLY reason a session looked like an LLM session
// was the spoofable env-var heuristic (S0-S6). SignalNone (no signal at all)
// was always a no-op. But every one of the heuristic's signals is entirely
// within the classified process's own control: an actual LLM agent could
// UNSET every known signal to present as SignalNone and sail straight through
// — the exact spoof-to-human attack this hardening pass exists to close.
//
// Fix (this file): stop gating on the *session classification* and instead
// gate on *what the command is about to hand the child process*. Only two
// CLI entry points ever expose a raw provider credential value to something
// outside keylatchd's control:
//
//   - `keylatch get` (prints the raw value to stdout)
//   - `keylatch run` in direct/brokered runtime modes — see
//     runtime.IsRawCredentialMode — which inject the raw secret into the
//     child process environment.
//
// `keylatch run` in gateway/proxy modes is deliberately NOT gated here: the
// child never receives anything but a scoped keylatch session token in that
// mode (runtime.DeliveryKeylatchSessionToken) — a spoofed-human session gains
// nothing by evading detection, so there is nothing to fail closed on.
//
// On a raw-exposure path, RequireVerifiedSession now requires POSITIVE
// corroboration — regardless of what ClassifySession says — before it will
// allow the command to proceed:
//
//   - a signed session ticket (KEYLATCH_LLM_TICKET is present), or
//   - keylatchd's authenticated IPC socket explicitly confirmed this PID is
//     an active, tracked session (llmcontext.SignalDaemonActive, via
//     KEYLATCH_DAEMON_SOCKET).
//
// Note what is deliberately NOT corroboration: a bare, unauthenticated
// reachability check against keylatchd's HTTP health endpoint (daemon.
// IsRunning — GET 127.0.0.1:7890/health) used to be accepted here as a third
// corroboration path. That check is session/PID-unbound — ANY local process
// can satisfy it merely by starting a listener on that port (e.g. `keylatch
// ui --port 7890 --no-open &`), which would defeat the raw-credential
// session gate's fail-closed intent (the exact spoof-to-human bypass this
// gate exists to close). It has been removed;
// keylatchd only helps here if it is actually tracking this specific session
// via its authenticated IPC socket (SignalDaemonActive) — merely being
// reachable is not enough.
//
// If neither the ticket nor SignalDaemonActive is present, the command fails
// closed with exitcode.SecurityBlock UNLESS the operator has explicitly
// opted out via KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 or the config.json
// "allow_unverified_session" field (see configAllowsUnverifiedSession) —
// either one restores the previous unrestricted behavior for that path.
//
// Human operators are not meant to trip this in normal use: a human running
// `keylatch get`/`keylatch run --runtime direct_brokered` by hand, without a
// keylatchd that is actively tracking this session and without ever having
// enabled the escape hatch, WILL be asked to provide a session ticket or flip
// the opt-out — this is the intended tradeoff (fail closed on an
// unauthenticated raw-credential path) and is why the opt-out exists as a
// first-class, permanent config field, not just an env var a human would
// have to remember every session.
const requireVerifiedSessionHint = "Provide a signed session ticket (KEYLATCH_LLM_TICKET), or set KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 (or allow_unverified_session in config) to restore unverified access. Note: keylatchd only helps if it is actively tracking this session via its IPC socket (KEYLATCH_DAEMON_SOCKET) — merely being reachable is not sufficient corroboration."

// RequireVerifiedSession enforces the raw-credential session gate for raw-credential-exposure paths.
//
// rawCredentialExposure must be true only when the calling command is about
// to hand a raw provider secret to something outside keylatchd's control —
// `get` always passes true; `run` passes runtime.IsRawCredentialMode(mode).
// Gateway/proxy `run` modes must pass false: this function is then a no-op
// and every session (human or LLM, verified or not) proceeds unaffected,
// because the child in those modes never sees a raw secret.
//
// configAllowsUnverified should be the resolved value of config.json's
// allow_unverified_session field (see configAllowsUnverifiedSession) — a
// second, permanent way for an operator to opt out of this check, alongside
// the KEYLATCH_ALLOW_UNVERIFIED_SESSION env var.
//
// Returns a non-nil error with actionable guidance when the command must fail
// closed; returns nil when it is safe to proceed to the command's existing
// (IsLLMSession-based) guards.
func RequireVerifiedSession(env llmcontext.Lookup, rawCredentialExposure bool, configAllowsUnverified bool) error {
	if !rawCredentialExposure {
		// Gateway/proxy mode (or a command that never returns a raw value):
		// the child/caller never receives anything but a scoped session
		// token or masked output. An unverified/spoofed session gains
		// nothing here, so there is nothing to gate.
		return nil
	}

	if env(llmcontext.EnvAllowUnverifiedSession) == "1" || configAllowsUnverified {
		return nil // explicit operator escape hatch (env or config) — restores old behavior
	}

	// Positive corroboration 1 & 2: a signed session ticket is present, or
	// keylatchd's IPC explicitly confirmed this PID as active. Ticket
	// presence here is the same presence-only fast path
	// llmcontext.ClassifySession uses for SignalTicket — full cryptographic
	// verification requires keylatchd's in-memory signing key and happens
	// elsewhere (llmcontext.VerifyTicket); it is a corroborating signal, not
	// a policy decision on its own (existing IsLLMSession-based guards remain
	// the authority for what the ticket permits). SignalDaemonError (IPC
	// configured but the query failed) is deliberately NOT treated as
	// corroboration — an error is not confirmation.
	switch llmcontext.ClassifySession(env) {
	case llmcontext.SignalTicket, llmcontext.SignalDaemonActive:
		return nil
	}

	return fmt.Errorf(
		"keylatch: this command exposes a raw credential value and no session "+
			"corroboration was found (no signed session ticket, keylatchd not "+
			"actively tracking this session) — refusing to proceed (fail closed). %s",
		requireVerifiedSessionHint)
}

// configAllowsUnverifiedSession loads config.json and reports whether the
// operator has permanently opted out of RequireVerifiedSession's fail-closed
// behavior via the "allow_unverified_session" field. Any load error (missing
// file, version mismatch, malformed JSON) is treated as "not opted out" —
// this helper fails closed, matching RequireVerifiedSession's own contract.
func configAllowsUnverifiedSession(env llmcontext.Lookup) bool {
	cfg, err := config.Load(paths.Config(env))
	if err != nil {
		return false
	}
	return cfg.AllowUnverifiedSession
}
