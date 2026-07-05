package cli

import (
	"context"
	"time"
)

// SecurityBlockEvent carries audit metadata for a blocked LLM-session attempt.
type SecurityBlockEvent struct {
	Command string   // argv[0] of the blocked command
	Signals []string // from llmcontext.Reasons()
	Time    time.Time
}

// SecurityBlockHook is called by GuardLLMSession on every block.
// A future release replaces this with the real audit writer. Default is a no-op.
var SecurityBlockHook func(ctx context.Context, e SecurityBlockEvent) = func(_ context.Context, _ SecurityBlockEvent) {}
