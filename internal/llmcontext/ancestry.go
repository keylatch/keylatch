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

func processChain() []Process { return chainFrom(os.Getpid()) }

// ChainOf returns the process pid followed by its ancestors, up to the first
// one that cannot be read. It is empty for a process that cannot be inspected.
func ChainOf(pid int) []Process {
	if pid <= 0 {
		return nil
	}
	return chainFrom(pid)
}

// HarnessOf returns the first harness any process of chain runs as.
func HarnessOf(chain []Process) (harness.Descriptor, bool) {
	for _, p := range chain {
		for _, name := range p.Names {
			if d, ok := harness.ByExecutable(name); ok {
				return d, true
			}
		}
	}
	return harness.Descriptor{}, false
}

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
