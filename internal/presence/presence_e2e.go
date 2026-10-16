//go:build keylatch_e2e

package presence

import (
	"os"
	"time"
)

// The end-to-end scripts drive privileged commands from a CI job with no
// terminal and no human. This file is compiled only into the binary those
// scripts build with -tags keylatch_e2e; a release binary has no such
// variable. The agent-ancestry check still runs.
func init() {
	if os.Getenv("KEYLATCH_E2E_PRESENCE") != "approve" {
		return
	}
	defaultR = &Requirer{
		Terminal: func() bool { return true },
		Ancestry: processAncestry,
		Ask:      func(Action, string) (bool, error) { return true, nil },
		Now:      time.Now,
	}
}
