package llmcontext

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// Environment names an earlier session check trusted. None of them may mark a
// process as anything, and none may hide a signal that fired.
var retiredSessionEnv = map[string]string{
	"KEYLATCH_LLM_TICKET":               "anything",
	"KEYLATCH_ALLOW_UNVERIFIED_SESSION": "1",
	"KEYLATCH_DAEMON_SOCKET":            filepath.Join(os.TempDir(), "keylatch-missing.sock"),
}

func withEnv(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestTicketVerifierErrorsNeverGrant(t *testing.T) {
	bound := []Process{{PID: 100, Start: 7}}
	failures := map[string]TicketVerifier{
		"expired": func(Lookup, string) (Ticket, error) { return Ticket{}, ErrTicketExpired },
		"invalid": func(Lookup, string) (Ticket, error) { return Ticket{}, ErrTicketInvalid },
		"key read error": func(Lookup, string) (Ticket, error) {
			return Ticket{}, errors.New("read session ticket key: permission denied")
		},
		"error with a bound ticket": func(Lookup, string) (Ticket, error) {
			return boundTicket, errors.New("verification failed")
		},
	}
	for name, verifier := range failures {
		t.Run(name, func(t *testing.T) {
			stubDetection(t, bound, verifier, false)

			c := Classify(mapLookup(map[string]string{TicketEnv: "ticket"}))
			if slices.Contains(c.Signals, SignalTicket) {
				t.Fatalf("a failed verification produced a ticket signal: %+v", c)
			}

			withHarness := Classify(mapLookup(map[string]string{TicketEnv: "ticket", "CLAUDECODE": "1"}))
			if !withHarness.Detected() || withHarness.Harness != "claude-code" {
				t.Fatalf("a failed ticket hid the harness signal: %+v", withHarness)
			}
		})
	}
}

func TestRetiredSessionEnvNeverRelaxes(t *testing.T) {
	stubDetection(t, []Process{{PID: 100, Start: 7}}, verifierAccepting("good"), false)

	if c := Classify(mapLookup(retiredSessionEnv)); slices.Contains(c.Signals, SignalTicket) {
		t.Fatalf("retired session variables produced a ticket signal: %+v", c)
	}

	for _, sig := range Signals {
		base := map[string]string{sig.EnvKey: "1"}
		want := Classify(mapLookup(base))
		got := Classify(mapLookup(withEnv(base, retiredSessionEnv)))
		if !got.Detected() {
			t.Fatalf("%s: retired session variables turned detection off", sig.EnvKey)
		}
		for _, s := range want.Signals {
			if !slices.Contains(got.Signals, s) {
				t.Fatalf("%s: signal %q lost when retired session variables are set", sig.EnvKey, s)
			}
		}
	}
}

// The daemon session query trusted any failure as an active session. Nothing
// may contact the socket a caller names in the environment.
func TestClassifyNeverQueriesDaemonSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket listener")
	}
	dir, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var dialed atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			_ = conn.Close()
		}
	}()

	stubDetection(t, []Process{{PID: 100, Start: 7}}, nil, false)
	env := mapLookup(map[string]string{"KEYLATCH_DAEMON_SOCKET": sock, "KEYLATCH_LLM_TICKET": "x"})
	if c := Classify(env); c.Detected() {
		t.Fatalf("daemon socket and legacy ticket variables classified the process: %+v", c)
	}
	time.Sleep(50 * time.Millisecond)
	if n := dialed.Load(); n != 0 {
		t.Fatalf("Classify contacted the daemon socket %d times", n)
	}
}
