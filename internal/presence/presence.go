// Package presence asks a human to approve a privileged action.
//
// Require needs three things at once: stdin and stderr are terminals, no
// ancestor of the process is a known agent harness, and the platform's own
// confirmation (polkit, LocalAuthentication, Windows Hello) succeeds where one
// is installed. In-user presence is friction, not a boundary: an agent that
// owns a pseudo-terminal it created itself could still type the answer. The
// ancestry check closes the common case, and a daemon-verified proof replaces
// this package behind the same interface.
//
// Nothing here reads the environment. A variable the caller controls could
// otherwise turn the check into a no-op, so the outcome depends only on file
// descriptors, the process tree and the platform prompt.
package presence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Action names the privileged operation being approved, for example
// "policy.change" or "gateway.token.create".
type Action string

// Proof records that a human approved one action. Digest binds the proof to
// the action and the summary the human read.
type Proof struct {
	Action   Action
	Digest   string
	Method   string
	IssuedAt time.Time
}

// Fresh reports whether the proof is at most max old.
func (p Proof) Fresh(now time.Time, max time.Duration) bool {
	return !p.IssuedAt.IsZero() && now.Sub(p.IssuedAt) <= max && !p.IssuedAt.After(now)
}

// Covers reports whether the proof was issued for exactly this action and
// summary.
func (p Proof) Covers(action Action, summary string) bool {
	return p.Digest != "" && p.Digest == Digest(action, summary)
}

// Digest is the hex SHA-256 over the action and the summary shown to the
// human.
func Digest(action Action, summary string) string {
	h := sha256.New()
	h.Write([]byte(action))
	h.Write([]byte{0})
	h.Write([]byte(summary))
	return hex.EncodeToString(h.Sum(nil))
}

var (
	// ErrNoTTY means stdin or stderr is not a terminal.
	ErrNoTTY = errors.New("presence: an interactive terminal is required")
	// ErrAgentTerminal means a known agent harness is an ancestor of this
	// process, so the terminal may be one the agent drives.
	ErrAgentTerminal = errors.New("presence: the terminal belongs to an agent session")
	// ErrDenied means the human declined, or the platform refused.
	ErrDenied = errors.New("presence: approval denied")
	// ErrUnavailable is returned by a Method that cannot run on this host. The
	// platform step is then skipped; the terminal step has already passed.
	ErrUnavailable = errors.New("presence: platform method unavailable")
)

// Method is a platform confirmation the user cannot answer from a script:
// polkit, LocalAuthentication or Windows Hello.
type Method interface {
	Name() string
	// Confirm returns nil when the user approved, ErrUnavailable when the
	// method cannot run here, and any other error when it refused.
	Confirm(ctx context.Context, action Action, summary string) error
}

// Requirer holds the collaborators of Require so tests can replace them.
type Requirer struct {
	// Terminal reports that stdin and stderr are terminals.
	Terminal func() bool
	// Ancestry returns the process and its ancestors.
	Ancestry func() []llmcontext.Process
	// Ask shows summary on the terminal and reports whether the human typed
	// the confirmation.
	Ask func(action Action, summary string) (bool, error)
	// Platform is the optional platform confirmation.
	Platform Method
	// Now supplies the issue time.
	Now func() time.Time
}

// New returns a Requirer wired to the real terminal, process tree and
// platform method.
func New() *Requirer {
	return &Requirer{
		Terminal: stdioIsTerminal,
		Ancestry: processAncestry,
		Ask:      askOnTerminal,
		Platform: platformMethod(),
		Now:      time.Now,
	}
}

func processAncestry() []llmcontext.Process {
	if testing.Testing() {
		return nil
	}
	return llmcontext.ChainOf(currentPID())
}

// Require asks the human to approve the action. The summary must name the
// action and its arguments, because it is the only thing the human reads.
func (r *Requirer) Require(ctx context.Context, action Action, summary string) (Proof, error) {
	summary = strings.TrimSpace(summary)
	if action == "" || summary == "" {
		return Proof{}, errors.New("presence: action and summary are required")
	}
	if !r.Terminal() {
		return Proof{}, fmt.Errorf("%w for %s; run this command yourself in a terminal, it cannot be scripted or piped", ErrNoTTY, action)
	}
	if d, ok := llmcontext.HarnessOf(r.Ancestry()); ok {
		return Proof{}, fmt.Errorf("%w (%s)", ErrAgentTerminal, d.ID)
	}
	approved, err := r.Ask(action, summary)
	if err != nil {
		return Proof{}, fmt.Errorf("presence: read confirmation: %w", err)
	}
	if !approved {
		return Proof{}, fmt.Errorf("%w: not confirmed on the terminal", ErrDenied)
	}
	method := "tty"
	if r.Platform != nil {
		switch err := r.Platform.Confirm(ctx, action, summary); {
		case err == nil:
			method = "tty+" + r.Platform.Name()
		case errors.Is(err, ErrUnavailable):
		default:
			return Proof{}, fmt.Errorf("%w: %s: %v", ErrDenied, r.Platform.Name(), err)
		}
	}
	return Proof{Action: action, Digest: Digest(action, summary), Method: method, IssuedAt: r.Now().UTC()}, nil
}

var (
	defaultMu sync.RWMutex
	defaultR  = New()
)

// Require asks with the default Requirer.
func Require(ctx context.Context, action Action, summary string) (Proof, error) {
	defaultMu.RLock()
	r := defaultR
	defaultMu.RUnlock()
	return r.Require(ctx, action, summary)
}

// SetDefault replaces the default Requirer and returns a function that
// restores the previous one. It exists for tests and panics outside them.
func SetDefault(r *Requirer) (restore func()) {
	if !testing.Testing() {
		panic("presence: SetDefault is only available in tests")
	}
	defaultMu.Lock()
	prev := defaultR
	defaultR = r
	defaultMu.Unlock()
	return func() {
		defaultMu.Lock()
		defaultR = prev
		defaultMu.Unlock()
	}
}

// Actions the CLI gates.
const (
	ActionBackendLogin Action = "backend.login"
	ActionBackupExport Action = "backup.export"
	// ActionBindingChange approves creating or widening a connection's binding,
	// bound to the exact host sets before and after.
	ActionBindingChange Action = "binding.change"
	// ActionLocalOnlyWeaken approves a weaker local-only delivery mode.
	ActionLocalOnlyWeaken Action = "local_only.weaken"
	// ActionApprove and ActionDeny decide one pending approval request, bound
	// to the request the human was shown.
	ActionApprove Action = "approval.approve"
	ActionDeny    Action = "approval.deny"
	// ActionRunApprove approves one contained run, bound to its exact plan.
	ActionRunApprove     Action = "run.approve"
	ActionConfigSet      Action = "config.set"
	ActionGatewayNoAudit Action = "gateway.no-audit"
	ActionGatewayToken   Action = "gateway.token.create"
	ActionGrantCreate    Action = "grant.create"
	ActionGrantRevoke    Action = "grant.revoke"
	ActionGuardUninstall Action = "guard.uninstall"
	ActionKeysRewrap     Action = "keys.rewrap"
	ActionPolicyChange   Action = "policy.change"
	ActionUIAdmin        Action = "ui.admin"
	// ActionKeyAllow approves adding or widening a key operation allowlist
	// entry, bound to the entry before and the additions requested.
	ActionKeyAllow Action = "key.allow"
)
