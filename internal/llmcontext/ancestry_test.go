package llmcontext

import (
	"os"
	"runtime"
	"testing"
)

func TestChainOfCurrentProcessStartsWithIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process table walk is covered by the platform tests")
	}
	chain := ChainOf(os.Getpid())
	if len(chain) < 2 || chain[0].PID != os.Getpid() {
		t.Fatalf("chain = %+v", chain)
	}
	if got := ChainOf(0); got != nil {
		t.Fatalf("pid 0 = %+v", got)
	}
}

func TestHarnessOfFindsTheFirstHarness(t *testing.T) {
	chain := []Process{{PID: 3, Names: []string{"sh"}}, {PID: 2, Names: []string{"/usr/bin/codex"}}, {PID: 1, Names: []string{"claude"}}}
	d, ok := HarnessOf(chain)
	if !ok || d.ID != "codex" {
		t.Fatalf("got %+v %v", d, ok)
	}
	if _, ok := HarnessOf([]Process{{Names: []string{"zsh"}}}); ok {
		t.Fatal("zsh is not a harness")
	}
}
