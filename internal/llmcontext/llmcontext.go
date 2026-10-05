// Package llmcontext classifies whether the current process runs inside an
// agent session. Its only internal import is internal/harness, the
// stdlib-only table of harness signals.
//
// Every signal can only make a decision stricter: a signal that fires marks
// the process as an agent; a missing, forged or stale signal changes
// nothing. A same-user agent can hide every signal, so detection is a label,
// never the thing that grants a privileged action.
package llmcontext

import (
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keylatch/keylatch/internal/harness"
)

// Lookup resolves an environment variable name to its value.
type Lookup func(string) string

// DefaultLookup resolves from the process environment.
var DefaultLookup Lookup = func(k string) string { return os.Getenv(k) }

// TicketEnv carries the session ticket `keylatch launch` hands to a harness.
const TicketEnv = "KEYLATCH_SESSION_TICKET"

// Signal labels for the non-environment signals.
const (
	SignalTicket         = "ticket"
	signalAncestryPrefix = "ancestry:"
)

// Classification is the result of Classify.
type Classification struct {
	// Signals names every signal that fired: environment variable names,
	// "ancestry:<harness>" and "ticket". Never contains values.
	Signals []string
	// Harness is the ID of the first harness a signal attributed, if any.
	Harness string
}

// Detected reports whether any signal fired.
func (c Classification) Detected() bool { return len(c.Signals) > 0 }

func (c *Classification) add(label, harnessID string) {
	c.Signals = append(c.Signals, label)
	if c.Harness == "" {
		c.Harness = harnessID
	}
}

// TicketVerifier checks a raw session ticket's signature and expiry. The
// process binding is checked by Classify.
type TicketVerifier func(env Lookup, raw string) (Ticket, error)

var ticketVerifier atomic.Pointer[TicketVerifier]

// SetTicketVerifier installs the verifier Classify uses for TicketEnv.
// Without one, a ticket is ignored.
func SetTicketVerifier(v TicketVerifier) {
	if v == nil {
		ticketVerifier.Store(nil)
		return
	}
	ticketVerifier.Store(&v)
}

// ErrTicketUnbound is reported when a valid ticket belongs to a process that
// is not an ancestor of this one.
var ErrTicketUnbound = errors.New("session ticket is not bound to this process tree")

// ancestrySignals is off in test binaries so that a developer running the
// test suite from inside an agent harness gets hermetic results; tests of
// ancestry detection turn it on explicitly.
var ancestrySignals = !testing.Testing()

var processChainFunc = processChain

// Classify evaluates the environment signals, the process ancestry and the
// session ticket.
func Classify(env Lookup) Classification {
	c := Classification{Signals: []string{}}
	for _, sig := range Signals {
		if sig.Match.Fires(env(sig.EnvKey)) {
			c.add(sig.Label, sig.Harness)
		}
	}

	raw := env(TicketEnv)
	if !ancestrySignals && raw == "" {
		return c
	}
	chain := processChainFunc()

	if ancestrySignals {
		seen := map[string]bool{}
		for _, p := range chain {
			for _, name := range p.Names {
				d, ok := harness.ByExecutable(name)
				if ok && !seen[d.ID] {
					seen[d.ID] = true
					c.add(signalAncestryPrefix+d.ID, d.ID)
				}
			}
		}
	}

	if raw != "" {
		if t, err := verifyBoundTicket(env, raw, chain); err != nil {
			warnRejectedTicket(err)
		} else {
			c.add(SignalTicket, t.Harness)
		}
	}
	return c
}

func verifyBoundTicket(env Lookup, raw string, chain []Process) (Ticket, error) {
	v := ticketVerifier.Load()
	if v == nil {
		return Ticket{}, errors.New("no session ticket verifier configured")
	}
	t, err := (*v)(env, raw)
	if err != nil {
		return Ticket{}, err
	}
	for _, p := range chain {
		if p.PID == t.PID && p.Start == t.ProcessStart {
			return t, nil
		}
	}
	return Ticket{}, ErrTicketUnbound
}

var rejectedTicketOnce sync.Once

func warnRejectedTicket(err error) {
	rejectedTicketOnce.Do(func() {
		slog.Warn("session ticket rejected", "error", err)
	})
}

// IsLLMSession reports whether any agent signal fired.
func IsLLMSession(env Lookup) bool {
	return Classify(env).Detected()
}

// Reasons returns the labels of the signals that fired; empty, never nil.
func Reasons(env Lookup) []string {
	return Classify(env).Signals
}
