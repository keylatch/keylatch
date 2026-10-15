// Package presencetest swaps the default presence Requirer in tests.
package presencetest

import (
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/presence"
)

// Approve makes presence.Require succeed for the rest of the test.
func Approve(tb testing.TB) {
	tb.Helper()
	tb.Cleanup(presence.SetDefault(Approver()))
}

// NoTerminal makes presence.Require fail as it does in an agent's tool call.
func NoTerminal(tb testing.TB) {
	tb.Helper()
	r := Approver()
	r.Terminal = func() bool { return false }
	tb.Cleanup(presence.SetDefault(r))
}

// Decline makes the human refuse.
func Decline(tb testing.TB) {
	tb.Helper()
	r := Approver()
	r.Ask = func(presence.Action, string) (bool, error) { return false, nil }
	tb.Cleanup(presence.SetDefault(r))
}

// Record makes presence.Require succeed and returns the summaries it was asked
// to approve.
func Record(tb testing.TB) *[]string {
	tb.Helper()
	var seen []string
	r := Approver()
	r.Ask = func(a presence.Action, summary string) (bool, error) {
		seen = append(seen, string(a)+": "+summary)
		return true, nil
	}
	tb.Cleanup(presence.SetDefault(r))
	return &seen
}

// Approver returns a Requirer that approves everything.
func Approver() *presence.Requirer {
	return &presence.Requirer{
		Terminal: func() bool { return true },
		Ancestry: func() []llmcontext.Process { return nil },
		Ask:      func(presence.Action, string) (bool, error) { return true, nil },
		Now:      time.Now,
	}
}
