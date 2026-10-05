//go:build linux

package llmcontext

import (
	"os"
	"slices"
	"testing"
)

func TestCurrentProcess_DescribesTheCaller(t *testing.T) {
	p, err := CurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != os.Getpid() || p.Start == 0 || len(p.Names) == 0 {
		t.Fatalf("process = %+v", p)
	}
}

func TestProcessChain_StartsAtTheCallerAndFollowsParents(t *testing.T) {
	chain := processChain()
	if len(chain) < 2 {
		t.Fatalf("chain = %+v", chain)
	}
	if chain[0].PID != os.Getpid() {
		t.Fatalf("chain starts at %d", chain[0].PID)
	}
	ppid, err := parentPID(os.Getpid())
	if err != nil || ppid != chain[1].PID {
		t.Fatalf("parent = %d, %v; chain[1] = %d", ppid, err, chain[1].PID)
	}
}

func TestProcFilesRejectUnknownProcesses(t *testing.T) {
	const missing = 1 << 30
	if _, _, err := statFields(missing); err == nil {
		t.Fatal("statFields accepted a missing process")
	}
	if _, err := readProcessInfo(missing); err == nil {
		t.Fatal("readProcessInfo accepted a missing process")
	}
	if _, err := parentPID(missing); err == nil {
		t.Fatal("parentPID accepted a missing process")
	}
}

func TestUniqueNames_NormalizesAndDropsDuplicates(t *testing.T) {
	got := uniqueNames("Node", "", "/usr/bin/node", "node", "claude")
	if slices.Contains(got, "") {
		t.Fatalf("empty name kept: %v", got)
	}
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] {
			t.Fatalf("duplicate %q in %v", n, got)
		}
		seen[n] = true
	}
	if !slices.Contains(got, "claude") {
		t.Fatalf("names = %v", got)
	}
}
