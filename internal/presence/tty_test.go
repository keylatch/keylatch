package presence

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	prev := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = prev; _ = r.Close() })
}

func TestAskOnTerminalOnlyYesApproves(t *testing.T) {
	for input, want := range map[string]bool{"yes\n": true, "  yes \n": true, "y\n": false, "\n": false, "no\n": false, "yes": true} {
		withStdin(t, input)
		got, err := askOnTerminal("policy.change", "allow x")
		if err != nil || got != want {
			t.Errorf("input %q: approved=%v err=%v, want %v", input, got, err, want)
		}
	}
	withStdin(t, "")
	if _, err := askOnTerminal("policy.change", "allow x"); err == nil {
		t.Error("end of input did not return an error")
	}
}

func TestTerminalHelpers(t *testing.T) {
	if currentPID() != os.Getpid() {
		t.Fatal("currentPID is not this process")
	}
	withStdin(t, "")
	if stdioIsTerminal() {
		t.Fatal("a pipe counted as a terminal")
	}
	if got := processAncestry(); got != nil {
		t.Fatalf("ancestry inside a test = %v", got)
	}
}

func TestDefaultRequirerIsReplaceable(t *testing.T) {
	r := &Requirer{
		Terminal: func() bool { return true },
		Ancestry: func() []llmcontext.Process { return nil },
		Ask:      func(Action, string) (bool, error) { return true, nil },
		Now:      time.Now,
	}
	restore := SetDefault(r)
	proof, err := Require(context.Background(), "policy.change", "allow x")
	if err != nil || proof.Action != "policy.change" || !proof.Covers("policy.change", "allow x") {
		t.Fatalf("proof = %+v, err %v", proof, err)
	}
	restore()
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	if defaultR == r {
		t.Fatal("restore left the replacement in place")
	}
}
