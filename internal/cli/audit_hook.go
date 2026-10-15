package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
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
	l, cleanup, err := openAuditLoggerFn()
	if err != nil {
		return
	}
	defer cleanup()
	_ = l.Log(ctx, audit.Event{
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

// recordBackupExport writes the audit event for a finished backup; a backup
// already on disk is not undone when the log is unavailable.
func recordBackupExport(ctx context.Context, connections int) {
	l, cleanup, err := openAuditLoggerFn()
	if err != nil {
		return
	}
	defer cleanup()
	_ = l.Log(ctx, audit.Event{
		Action:  audit.ActionBackupExport,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"destination_kind": "file",
			"caller_kind":      callerKindOfProcess(),
			"reason":           fmt.Sprintf("%d connections", connections),
		},
	})
}

// recordCall writes the single audit event for one `keylatch call`.
func recordCall(ctx context.Context, l *audit.Logger, connection, action string, res *runner.ActionResult, callErr error) {
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
			"caller_kind": callerKindOfProcess(),
			"status":      status,
		},
	})
}
