package callerkind

import (
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

func chainOf(names ...string) func(int) []llmcontext.Process {
	return func(int) []llmcontext.Process {
		var out []llmcontext.Process
		for i, n := range names {
			out = append(out, llmcontext.Process{PID: i + 1, Names: []string{n}})
		}
		return out
	}
}

func TestPeerClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chain   func(int) []llmcontext.Process
		ev      Evidence
		kind    Kind
		harness string
		reason  string
	}{
		{"plain peer in the daemon's namespaces", chainOf("zsh", "tmux"), Evidence{SharesNamespaces: true}, Human, "", ""},
		{"client signal", chainOf("zsh"), Evidence{SharesNamespaces: true, Signals: []string{"CLAUDECODE"}}, Agent, "", "signals"},
		{"valid ticket", chainOf("zsh"), Evidence{SharesNamespaces: true, TicketValid: true}, Agent, "", "ticket"},
		{"harness ancestor and no signals", chainOf("sh", "node", "claude", "zsh"), Evidence{SharesNamespaces: true}, Agent, "claude-code", "ancestry:claude-code"},
		{"harness ancestor outside the namespaces", chainOf("sh", "codex"), Evidence{}, Agent, "codex", "ancestry:codex"},
		{"outside the namespaces", chainOf("sh"), Evidence{}, Host, "", "outside-namespaces"},
		{"relay with no agent evidence", chainOf(RelayExecutable, "sh"), Evidence{SharesNamespaces: true}, Host, "", "relay"},
		{"relay below a harness", chainOf(RelayExecutable, "claude"), Evidence{SharesNamespaces: true}, Agent, "claude-code", "ancestry:claude-code"},
		{"unreadable ancestry", func(int) []llmcontext.Process { return nil }, Evidence{SharesNamespaces: true}, Human, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := (&Classifier{Chain: tc.chain}).Peer(tc.ev)
			if got.Kind != tc.kind || got.Harness != tc.harness {
				t.Fatalf("got %+v, want %s/%s", got, tc.kind, tc.harness)
			}
			if tc.reason != "" && !slices.Contains(got.Reasons, tc.reason) {
				t.Errorf("reasons %v lack %q", got.Reasons, tc.reason)
			}
		})
	}
}

func TestSignalsOnlyTighten(t *testing.T) {
	c := &Classifier{Chain: chainOf("zsh")}
	if got := c.Peer(Evidence{SharesNamespaces: true}); got.Kind != Human {
		t.Fatalf("baseline = %s", got.Kind)
	}
	if got := c.Peer(Evidence{SharesNamespaces: true, Signals: []string{"x"}}); got.Kind != Agent {
		t.Fatalf("a signal must move a caller to agent, got %s", got.Kind)
	}
	// A client that sends nothing cannot erase what the daemon observed.
	a := &Classifier{Chain: chainOf("claude")}
	if got := a.Peer(Evidence{SharesNamespaces: true}); got.Kind != Agent {
		t.Fatalf("observed ancestry must stand without signals, got %s", got.Kind)
	}
}

func TestConstrained(t *testing.T) {
	for k, want := range map[Kind]bool{Human: false, Agent: true, Host: true, Service: true} {
		if k.Constrained() != want {
			t.Errorf("%s.Constrained() = %v", k, !want)
		}
	}
}

func TestDefaultChainIsEmptyInTestBinaries(t *testing.T) {
	var c *Classifier
	if got := c.chain(os.Getpid()); got != nil {
		t.Fatalf("test binaries must not read the real process tree, got %v", got)
	}
	if got := c.Peer(Evidence{SharesNamespaces: true}); got.Kind != Human {
		t.Fatalf("got %s", got.Kind)
	}
}

func TestLocal(t *testing.T) {
	env := func(m map[string]string) llmcontext.Lookup { return func(k string) string { return m[k] } }
	for _, tc := range []struct {
		name        string
		env         map[string]string
		interactive bool
		kind        Kind
	}{
		{"agent signal wins over a terminal", map[string]string{"CLAUDECODE": "1"}, true, Agent},
		{"agent signal wins over a service", map[string]string{"CLAUDECODE": "1", "INVOCATION_ID": "x"}, false, Agent},
		{"service unit", map[string]string{"INVOCATION_ID": "x"}, false, Service},
		{"terminal", nil, true, Human},
		{"neither", nil, false, Host},
	} {
		if got := Local(env(tc.env), tc.interactive); got.Kind != tc.kind {
			t.Errorf("%s: %s, want %s", tc.name, got.Kind, tc.kind)
		}
	}
	if got := Local(env(map[string]string{"CLAUDECODE": "1"}), true); got.Harness == "" || len(got.Reasons) == 0 {
		t.Errorf("agent result lacks evidence: %+v", got)
	}
}

func TestSharesNamespaces(t *testing.T) {
	if SharesNamespaces(0) {
		t.Error("an unknown peer must not share namespaces")
	}
	if runtime.GOOS == "linux" {
		if !SharesNamespaces(os.Getpid()) {
			t.Error("a process shares its own namespaces")
		}
		if SharesNamespaces(1 << 30) {
			t.Error("a process that cannot be inspected must not share namespaces")
		}
	}
}
