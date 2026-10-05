package llmcontext

import (
	"os"

	"github.com/keylatch/keylatch/internal/harness"
)

// Process is one entry of the current process's ancestry.
type Process struct {
	PID int
	// Start is an opaque, platform-specific start time that changes when a
	// PID is reused.
	Start uint64
	// Names holds the normalized executable names the process is known by
	// (command name, executable base name, argv[0] base name).
	Names []string
}

// maxAncestry bounds the walk; real process trees are far shallower.
const maxAncestry = 64

// CurrentProcess describes the calling process.
func CurrentProcess() (Process, error) {
	return readProcessInfo(os.Getpid())
}

func uniqueNames(names ...string) []string {
	var out []string
	for _, n := range names {
		n = harness.NormalizeExecutable(n)
		if n == "" {
			continue
		}
		dup := false
		for _, o := range out {
			if o == n {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, n)
		}
	}
	return out
}
