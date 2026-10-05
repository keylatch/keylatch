package llmcontext

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func mapLookup(m map[string]string) Lookup { return func(k string) string { return m[k] } }

// stubDetection replaces the process chain and ticket verifier for one test.
// Tests using it must not run in parallel.
func stubDetection(t *testing.T, chain []Process, verifier TicketVerifier, ancestry bool) {
	t.Helper()
	prevChain, prevAncestry := processChainFunc, ancestrySignals
	prevVerifier := ticketVerifier.Load()
	processChainFunc = func() []Process { return chain }
	ancestrySignals = ancestry
	SetTicketVerifier(verifier)
	t.Cleanup(func() {
		processChainFunc, ancestrySignals = prevChain, prevAncestry
		ticketVerifier.Store(prevVerifier)
	})
}

var boundTicket = Ticket{SessionID: "s", Harness: "codex", PID: 100, ProcessStart: 7}

func verifierAccepting(raw string) TicketVerifier {
	return func(_ Lookup, got string) (Ticket, error) {
		if got != raw {
			return Ticket{}, ErrTicketInvalid
		}
		return boundTicket, nil
	}
}

func TestClassify_TicketBoundToAncestor(t *testing.T) {
	chain := []Process{{PID: 300, Start: 1, Names: []string{"keylatch"}}, {PID: 100, Start: 7, Names: []string{"keylatch"}}}
	stubDetection(t, chain, verifierAccepting("good"), false)

	c := Classify(mapLookup(map[string]string{TicketEnv: "good"}))
	if !slices.Equal(c.Signals, []string{SignalTicket}) || c.Harness != "codex" {
		t.Fatalf("valid bound ticket: got %+v", c)
	}
}

func TestClassify_RejectsUnboundForgedOrUnverifiedTicket(t *testing.T) {
	reused := []Process{{PID: 300, Start: 1}, {PID: 100, Start: 8}}
	stubDetection(t, reused, verifierAccepting("good"), false)
	if c := Classify(mapLookup(map[string]string{TicketEnv: "good"})); c.Detected() {
		t.Fatalf("ticket for a reused PID must not count: %+v", c)
	}
	if _, err := verifyBoundTicket(mapLookup(nil), "good", reused); !errors.Is(err, ErrTicketUnbound) {
		t.Fatalf("want ErrTicketUnbound, got %v", err)
	}

	bound := []Process{{PID: 100, Start: 7}}
	stubDetection(t, bound, verifierAccepting("good"), false)
	if c := Classify(mapLookup(map[string]string{TicketEnv: "forged"})); c.Detected() {
		t.Fatalf("forged ticket must not count: %+v", c)
	}

	stubDetection(t, bound, nil, false)
	if c := Classify(mapLookup(map[string]string{TicketEnv: "good"})); c.Detected() {
		t.Fatalf("ticket without a verifier must not count: %+v", c)
	}
}

func TestClassify_AncestrySignal(t *testing.T) {
	chain := []Process{{PID: 3, Names: []string{"keylatch"}}, {PID: 2, Names: []string{"bash"}}, {PID: 1, Names: []string{"node", "claude"}}}
	stubDetection(t, chain, nil, true)
	c := Classify(mapLookup(nil))
	if !slices.Equal(c.Signals, []string{"ancestry:claude-code"}) || c.Harness != "claude-code" {
		t.Fatalf("got %+v", c)
	}
}

// TestDetectionNeverRelaxes draws random signal sets and checks that removing
// signals never turns a detection off unless every signal is gone, and that
// the fired signals of a subset are a subset of the fired signals of the set.
func TestDetectionNeverRelaxes(t *testing.T) {
	type candidate struct {
		env  [2]string
		exe  string
		good bool
	}
	var pool []candidate
	for _, s := range Signals {
		pool = append(pool, candidate{env: [2]string{s.EnvKey, "1"}})
	}
	for _, exe := range []string{"claude", "codex", "cursor-agent", "gemini", "opencode", "aider", "copilot", "bash", "node"} {
		pool = append(pool, candidate{exe: exe})
	}
	pool = append(pool, candidate{good: true}, candidate{env: [2]string{TicketEnv, "forged"}})

	classify := func(set []candidate) Classification {
		env := map[string]string{}
		chain := []Process{{PID: 100, Start: 7, Names: []string{"keylatch"}}}
		for _, c := range set {
			switch {
			case c.good:
				env[TicketEnv] = "good"
			case c.exe != "":
				chain = append(chain, Process{PID: 1, Start: 1, Names: []string{c.exe}})
			default:
				if c.env[0] != TicketEnv || env[TicketEnv] == "" {
					env[c.env[0]] = c.env[1]
				}
			}
		}
		stubDetection(t, chain, verifierAccepting("good"), true)
		return Classify(mapLookup(env))
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		var full []candidate
		for _, c := range pool {
			if rng.Intn(4) == 0 {
				full = append(full, c)
			}
		}
		var sub []candidate
		for _, c := range full {
			if rng.Intn(2) == 0 {
				sub = append(sub, c)
			}
		}
		big, small := classify(full), classify(sub)
		if small.Detected() && !big.Detected() {
			t.Fatalf("adding signals relaxed the decision: subset %v detected, superset %v not", sub, full)
		}
		for _, s := range small.Signals {
			if !slices.Contains(big.Signals, s) {
				t.Fatalf("signal %q fired for subset but not for superset", s)
			}
		}
	}
}

const ancestryRoleEnv = "KEYLATCH_ANCESTRY_TEST_ROLE"

// TestAncestryDetectsHarness runs a copy of the test binary named like the
// Claude Code executable, which starts a child with an environment holding
// no agent variable. The child must still classify as an agent.
func TestAncestryDetectsHarness(t *testing.T) {
	switch os.Getenv(ancestryRoleEnv) {
	case "harness":
		child := exec.Command(os.Getenv("KEYLATCH_ANCESTRY_TEST_BINARY"), "-test.run=^TestAncestryDetectsHarness$")
		child.Env = []string{ancestryRoleEnv + "=child", "PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Run(); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	case "child":
		ancestrySignals = true
		_, _ = io.WriteString(os.Stdout, "signals="+strings.Join(Classify(mapLookup(nil)).Signals, ",")+"\n")
		os.Exit(0)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "claude"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	harnessBin := filepath.Join(t.TempDir(), name)
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harnessBin, data, 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(harnessBin, "-test.run=^TestAncestryDetectsHarness$")
	cmd.Env = []string{ancestryRoleEnv + "=harness", "KEYLATCH_ANCESTRY_TEST_BINARY=" + self, "PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("harness process: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ancestry:claude-code") {
		t.Fatalf("child of a process named claude was not classified as an agent:\n%s", out)
	}
}

func TestClassify_LogsRejectedTicket(t *testing.T) {
	stubDetection(t, []Process{{PID: 100, Start: 7}}, verifierAccepting("good"), false)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	rejectedTicketOnce = sync.Once{}
	t.Cleanup(func() { slog.SetDefault(prev) })

	Classify(mapLookup(map[string]string{TicketEnv: "forged"}))
	if !strings.Contains(buf.String(), "session ticket rejected") {
		t.Fatalf("forged ticket was not logged: %q", buf.String())
	}
}
