//go:build harness

package harness

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// runRow runs one scenario row through the shipped binary and reports whether
// the agent was stopped.
func runRow(t *testing.T, id string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("scenario steps are bash commands")
	}
	for _, s := range scenarios {
		if s.id != id {
			continue
		}
		w := newWorld(t, "claude-code")
		outs := w.run("claude-code", s)
		for i, o := range outs {
			t.Logf("step %d: blocked=%v exit=%d reason=%q\nstdout: %.600q\nstderr: %.600q", i, o.Blocked, o.ExitCode, o.Reason, o.Stdout, o.Stderr)
		}
		assert.Equal(t, wantBlocked, w.verdictOf(s, outs), "%s: %s", s.id, s.description)
		return
	}
	t.Fatalf("no scenario row %q", id)
}

func TestScenarioSyncApplyByAgent(t *testing.T)    { runRow(t, "sync-apply-by-agent") }
func TestScenarioSyncValueOnSocket(t *testing.T)   { runRow(t, "sync-value-on-socket") }
func TestScenarioSyncValueInAgentEnv(t *testing.T) { runRow(t, "sync-value-in-agent-env") }
