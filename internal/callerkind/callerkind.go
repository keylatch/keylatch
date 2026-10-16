// Package callerkind is the one place that decides what kind of caller is
// asking: a human, an agent session, a service unit or a host process that
// shows no agent evidence. The control socket, the ssh-agent socket, key
// operations and the mint policy all take their answer from here.
//
// Evidence only ever moves a caller away from human. A client can add
// signals but never remove what the daemon observed itself.
package callerkind

import (
	"slices"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Kind classifies a caller.
type Kind string

const (
	// Human is a same-user process in the daemon's own namespaces with no
	// agent evidence.
	Human Kind = "human"
	// Agent is a caller with agent evidence: a harness signal, a valid session
	// ticket, or a harness among its ancestors.
	Agent Kind = "agent"
	// Service is a process started by a service manager unit.
	Service Kind = "service"
	// Host is the residual class: a same-user caller outside the daemon's
	// namespaces, such as a process inside a harness sandbox, or a caller that
	// is neither interactive nor a service.
	Host Kind = "host"
)

// Constrained reports whether the kind may not receive secret values.
func (k Kind) Constrained() bool { return k != Human }

// Result is a classification and the evidence behind it. Reasons, Harness and
// Unit never contain values.
type Result struct {
	Kind    Kind
	Harness string
	// Unit is the systemd service unit of a Service caller.
	Unit    string
	Reasons []string
}

// Evidence is what the daemon knows about a socket peer.
type Evidence struct {
	// PID is the peer's process, or 0 when the daemon cannot see it.
	PID int
	// SharesNamespaces reports that the peer lives in the daemon's own PID,
	// mount, user and network namespaces.
	SharesNamespaces bool
	// Signals are the agent signals the client reports from its own
	// environment.
	Signals []string
	// TicketValid reports that the client presented a valid session ticket.
	TicketValid bool
	// Cgroup is the peer's control group path, when the daemon pinned the
	// process.
	Cgroup string
}

// Classifier classifies socket peers. The zero value walks the real process
// tree.
type Classifier struct {
	// Chain returns a process and its ancestors. Nil selects the platform's
	// process table; in test binaries that is empty so a suite run inside an
	// agent harness stays hermetic.
	Chain func(pid int) []llmcontext.Process
	// AgentScope reports that a control group belongs to a launcher-registered
	// agent scope.
	AgentScope func(cgroup string) bool
	// NoHuman makes a peer without agent evidence a host. A broker daemon sets
	// it: a human is whoever holds a presence proof for the request, and that
	// is decided per request, never from the peer.
	NoHuman bool
}

func (c *Classifier) chain(pid int) []llmcontext.Process {
	if c != nil && c.Chain != nil {
		return c.Chain(pid)
	}
	if testing.Testing() {
		return nil
	}
	return llmcontext.ChainOf(pid)
}

// Peer classifies a socket peer. Agent evidence wins over everything: a
// sandboxed agent that hides its signals is still found by its ancestry, and
// one that hides everything lands in Host, never Human.
func (c *Classifier) Peer(ev Evidence) Result {
	r := Result{}
	if len(ev.Signals) > 0 {
		r.Reasons = append(r.Reasons, "signals")
	}
	if ev.TicketValid {
		r.Reasons = append(r.Reasons, llmcontext.SignalTicket)
	}
	chain := c.chain(ev.PID)
	if d, ok := llmcontext.HarnessOf(chain); ok {
		r.Harness = d.ID
		r.Reasons = append(r.Reasons, "ancestry:"+d.ID)
	}
	if ev.Cgroup != "" && c != nil && c.AgentScope != nil && c.AgentScope(ev.Cgroup) {
		r.Reasons = append(r.Reasons, "agent-scope")
	}
	switch {
	case len(r.Reasons) > 0:
		r.Kind = Agent
	case isRelay(chain):
		r.Kind, r.Reasons = Host, []string{"relay"}
	case c != nil && c.NoHuman:
		r.Kind, r.Reasons = Host, []string{"no-presence-proof"}
	case !ev.SharesNamespaces:
		r.Kind, r.Reasons = Host, []string{"outside-namespaces"}
	default:
		r.Kind = Human
	}
	return r
}

// Local classifies the current process. An agent session wins; a process in a
// non-transient systemd service unit, read from its cgroup and confirmed with
// systemd, is a service; an interactive terminal is a human; the rest is
// host. A hidden agent counts as host, so policy bounds what a host can do.
// Service classification is advisory until the broker daemon enrolls units.
func Local(env llmcontext.Lookup, interactive bool) Result {
	if cl := llmcontext.Classify(env); cl.Detected() {
		return Result{Kind: Agent, Harness: cl.Harness, Reasons: cl.Signals}
	}
	if unit, ok := serviceUnit(); ok {
		return Result{Kind: Service, Unit: unit, Reasons: []string{"unit:" + unit}}
	}
	switch {
	case interactive:
		return Result{Kind: Human}
	default:
		return Result{Kind: Host}
	}
}

// RelayExecutable is the name of the excluded fallback binary that forwards a
// sandboxed caller's requests. A peer running as it is never a human: the
// bytes it forwards come from whoever invoked it.
const RelayExecutable = "keylatch-relay"

func isRelay(chain []llmcontext.Process) bool {
	return len(chain) > 0 && slices.Contains(chain[0].Names, RelayExecutable)
}
