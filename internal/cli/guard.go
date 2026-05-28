package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// S-INV-2 call-site coverage table (EPIC-05 Task 1)
//
// Every site that calls backend.Get / vault.Get / store.Get in the CLI is
// classified below. Classification key:
//
//	(A) wrapped by AsValueBearing / GuardRuntime — blocked at entry
//	(B) guarded by explicit llmcontext.IsLLMSession check in the handler
//	(C) provably unreachable in LLM sessions (terminal/interactive requirement)
//
// | Call site                                          | File                      | Class | Reason                                                  |
// |----------------------------------------------------|---------------------------|-------|---------------------------------------------------------|
// | newGetCmd → AsValueBearing(notImpl)                | root.go:412               | A     | AsValueBearing wraps the handler; blocks exit 2         |
// | newPhase3TestCmd → connections.Test → store.Get    | cmd_status.go:26          | B     | IsLLMSession guard added at cmd entry (T-04-01)         |
// | newPhase3DescribeCmd → connections.Describe        | cmd_status.go:216         | A     | describe never calls store.Get for raw values (metadata only) |
// | newListCmdImpl → backend.List (no Get)             | list_cmd.go:51            | A     | list only enumerates keys, never reads values           |
// | newRunCmd → GuardRuntime → runner.Get              | root.go:478               | A     | GuardRuntime blocks disallowed modes; gateway path never returns raw value to agent |
// | newBackupCmd → store.Get                           | cmd_backup.go:26          | B     | explicit IsLLMSession check at handler entry (T-12-02)  |
// | newDestroyVersionCmd / newRollbackCmd              | rollback_cmd.go           | B     | explicit IsLLMSession check at handler entry (S4-8)     |
// | connections.RunTestStrategy → store.Get            | cmd_connect.go            | B     | connect blocked in LLM sessions via IsLLMSession check  |
// | proxy/server.go → Vault.Get                       | proxy/server.go:156       | C     | gateway_proxy driver starts proxy in parent process;    |
// |                                                    |                           |       | parent already passed LLM guard before arriving here    |
// | runner/process_runner.go → Backend.Get            | runner/process_runner.go:127 | A  | runner invoked only after GuardRuntime passes; gateway  |
// |                                                    |                           |       | modes never expose raw value to agent stdout            |
// | runner/driver_brokered.go → vault.Get             | runner/driver_brokered.go:101 | A | same — runner path, guarded by GuardRuntime at entry   |
// | internal/backend/vault/vault.go → client.Get      | backend/vault/vault.go    | C     | called only via dispatchedStore which is always mediated|
// |                                                    |                           |       | by one of the guards above                              |
//
// Any new store.Get caller MUST be classified here and added to TestSINV2_AllSixCommands.

// GuardLLMSession wraps a Handler so it is unreachable inside an LLM session.
// S0-1: no credential bytes reach stdout when blocked.
// S0-3: there is no bypass path — the only way to construct a ValueBearingHandler is AsValueBearing.
// S0-5: GuardLLMSession is applied only to value-bearing commands (get, export, dump).
func GuardLLMSession(inner Handler) Handler {
	return func(ctx context.Context, args HandlerArgs) (Result, error) {
		if llmcontext.IsLLMSession(args.Env) {
			// S0-4: exit SecurityBlocked, print to stderr only — never stdout.
			reasons := llmcontext.Reasons(args.Env)
			fmt.Fprintf(args.Stderr, "Error: Blocked in LLM session — 'get' would expose raw credential values.\n\n")
			if len(reasons) > 0 {
				fmt.Fprintf(args.Stderr, "  Detected via: %s\n\n", strings.Join(reasons, ", "))
			}
			fmt.Fprintf(args.Stderr, "  Use --masked to retrieve a redacted value (safe in AI sessions):\n")
			fmt.Fprintf(args.Stderr, "    keylatch get --masked <service> <key>\n\n")
			fmt.Fprintf(args.Stderr, "  Or use one of these safe alternatives:\n")
			fmt.Fprintf(args.Stderr, "    keylatch list           — list connections without values\n")
			fmt.Fprintf(args.Stderr, "    keylatch describe       — show connection metadata\n")
			fmt.Fprintf(args.Stderr, "    keylatch run <conn> --  — run a command with injected credentials\n")

			SecurityBlockHook(ctx, SecurityBlockEvent{
				Command: commandName(args),
				Signals: reasons,
				Time:    time.Now(),
			})

			return Result{ExitCode: exitcode.SecurityBlock}, nil
		}
		return inner(ctx, args)
	}
}

// ValueBearingHandler is a typed wrapper for handlers that produce credential values.
// The unexported field prevents construction outside this package — callers must use AsValueBearing.
type ValueBearingHandler struct {
	inner Handler
	_     struct{} // prevents direct struct-literal construction outside package
}

// AsValueBearing wraps inner with GuardLLMSession and returns a ValueBearingHandler.
// This is the ONLY way to construct a ValueBearingHandler.
func AsValueBearing(inner Handler) ValueBearingHandler {
	return ValueBearingHandler{inner: GuardLLMSession(inner)}
}

// Invoke calls the guarded inner handler.
func (v ValueBearingHandler) Invoke(ctx context.Context, args HandlerArgs) (Result, error) {
	return v.inner(ctx, args)
}

func commandName(args HandlerArgs) string {
	if len(args.Positional) > 0 {
		return args.Positional[0]
	}
	return "unknown"
}
