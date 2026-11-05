package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/runner"
)

// SecurityBlockEvent carries audit metadata for a blocked LLM-session attempt.
type SecurityBlockEvent struct {
	Command string   // argv[0] of the blocked command
	Signals []string // from llmcontext.Reasons()
	Time    time.Time
}

// SecurityBlockHook is called by GuardLLMSession on every block. It records a
// value-free security.block event; a block never depends on the audit log
// being writable, so failures to record are dropped.
var SecurityBlockHook func(ctx context.Context, e SecurityBlockEvent) = recordSecurityBlock

func recordSecurityBlock(ctx context.Context, e SecurityBlockEvent) {
	recordEvent(ctx, audit.Event{
		Timestamp: e.Time,
		Action:    audit.ActionSecurityBlock,
		Outcome:   audit.OutcomeDenied,
		Extra: map[string]any{
			"command":     e.Command,
			"signals":     e.Signals,
			"caller_kind": "agent",
		},
	})
}

// recordEvent writes ev to the audit log for an action that has already
// happened or been refused. A log that cannot be opened loses the event; it
// never undoes the action or turns a refusal into something else.
func recordEvent(ctx context.Context, ev audit.Event) {
	l, cleanup, err := openAuditLoggerFn()
	if err != nil {
		return
	}
	defer cleanup()
	_ = l.Log(ctx, ev)
}

// recordBackupExport writes the audit event for a finished backup.
func recordBackupExport(ctx context.Context, connections int) {
	recordEvent(ctx, audit.Event{
		Action:  audit.ActionBackupExport,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"destination_kind": "file",
			"caller_kind":      callerKindOfProcess(),
			"reason":           fmt.Sprintf("%d connections", connections),
		},
	})
}

// recordPresenceDecision writes the outcome of one human-presence check.
func recordPresenceDecision(ctx context.Context, action presence.Action, proof presence.Proof, err error) {
	ev := audit.Event{
		Action:  audit.ActionPresenceDecision,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"operation":   string(action),
			"method":      proof.Method,
			"result":      "approved",
			"digest":      proof.Digest,
			"caller_kind": callerKindOfProcess(),
		},
	}
	if err != nil {
		ev.Outcome = audit.OutcomeDenied
		ev.Extra["result"] = presenceResult(err)
		ev.Extra["reason"] = err.Error()
	}
	recordEvent(ctx, ev)
}

func presenceResult(err error) string {
	switch {
	case errors.Is(err, presence.ErrNoTTY):
		return "no_terminal"
	case errors.Is(err, presence.ErrAgentTerminal):
		return "agent_terminal"
	case errors.Is(err, presence.ErrDenied):
		return "denied"
	}
	return "error"
}

// recordPolicyChange writes the event for an edit to policy or grants.
// connection is empty when the change is not about one connection; reason
// carries why a refused change was refused.
func recordPolicyChange(ctx context.Context, outcome audit.Outcome, change, connection, digest, reason string) {
	extra := map[string]any{
		"change":      change,
		"caller_kind": callerKindOfProcess(),
	}
	for k, v := range map[string]string{"connection": connection, "digest": digest, "reason": reason} {
		if v != "" {
			extra[k] = v
		}
	}
	recordEvent(ctx, audit.Event{Action: audit.ActionPolicyChange, Outcome: outcome, Extra: extra})
}

// recordGuardBlock writes the event for a command a guard refused before it
// ran. command is the verb, never its arguments.
func recordGuardBlock(ctx context.Context, command, rule, reason string) {
	recordEvent(ctx, audit.Event{
		Action:  audit.ActionGuardBlock,
		Outcome: audit.OutcomeDenied,
		Extra: map[string]any{
			"command":     command,
			"rule":        rule,
			"caller_kind": callerKindOfProcess(),
			"reason":      reason,
		},
	})
}

// recordSet writes the event for one secret field written; path is a vault
// path or its shorthand, and only the connection and field names are kept.
func recordSet(ctx context.Context, l *audit.Logger, path, backend string, err error) {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '.' })
	connection, field := path, ""
	if n := len(parts); n >= 2 {
		connection, field = parts[n-2], parts[n-1]
	}
	extra := map[string]any{
		"connection":  connection,
		"field":       field,
		"backend":     backend,
		"caller_kind": callerKindOfProcess(),
	}
	outcome := audit.OutcomeOK
	if err != nil {
		outcome = audit.OutcomeError
		extra["reason"] = "write failed"
	}
	_ = l.Log(ctx, audit.Event{Action: audit.ActionSet, Outcome: outcome, Extra: extra})
}

// recordConnect writes the event for a connection create or update.
func recordConnect(ctx context.Context, connection, backend string, err error) {
	extra := map[string]any{
		"connection":  connection,
		"backend":     backend,
		"caller_kind": callerKindOfProcess(),
	}
	outcome := audit.OutcomeOK
	if err != nil {
		outcome = audit.OutcomeError
		extra["reason"] = "connect failed"
	}
	recordEvent(ctx, audit.Event{Action: audit.ActionConnect, Outcome: outcome, Extra: extra})
}

// recordCall writes the single audit event for one `keylatch call`.
func recordCall(ctx context.Context, l *audit.Logger, connection, action string, kind callerkind.Kind, res *runner.ActionResult, callErr error) {
	outcome, status := audit.OutcomeOK, 0
	if res != nil {
		status = res.StatusCode
	}
	if callErr != nil || status < 200 || status >= 300 {
		outcome = audit.OutcomeError
	}
	_ = l.Log(ctx, audit.Event{
		Action:  audit.ActionCall,
		Outcome: outcome,
		Extra: map[string]any{
			"connection":  connection,
			"action":      action,
			"caller_kind": string(kind),
			"status":      status,
		},
	})
}

// recordCallDenied writes the single audit event for a call policy refused.
func recordCallDenied(ctx context.Context, l *audit.Logger, connection, action string, kind callerkind.Kind, reason string) {
	_ = l.Log(ctx, audit.Event{
		Action:  audit.ActionCall,
		Outcome: audit.OutcomeDenied,
		Extra: map[string]any{
			"connection":  connection,
			"action":      action,
			"caller_kind": string(kind),
			"reason":      reason,
		},
	})
}
