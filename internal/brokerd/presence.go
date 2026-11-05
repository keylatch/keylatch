package brokerd

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
)

// ProofTTL is how long a presence proof stays valid. A proof is single use.
const ProofTTL = 60 * time.Second

// polkitAction is declared in packaging/linux/polkit/dev.keylatch.policy with
// auth_self: the user's own password every time, nothing retained
// (auth_self_keep is never used).
const polkitAction = "dev.keylatch.privileged"

// Presence errors. A proof that is unknown, spent or never issued is reported
// the same way, so a caller learns nothing about proofs it does not hold.
var (
	ErrPresenceRequired    = errors.New("brokerd: this request needs a presence proof")
	ErrProofInvalid        = errors.New("brokerd: the presence proof is not valid for this request")
	ErrProofExpired        = errors.New("brokerd: the presence proof has expired")
	ErrPresenceUnavailable = errors.New("brokerd: the daemon has no way to verify presence on this host")
	ErrAgentPresence       = errors.New("brokerd: an agent session cannot ask for presence")
)

// Subject is the process presence is asked for: the peer, never the daemon.
type Subject struct {
	PID   int
	Start string
	UID   uint32
}

// PresenceMethod verifies that the human at the machine approved an action.
type PresenceMethod interface {
	Name() string
	Verify(ctx context.Context, subject Subject, action, summary string) error
}

// Polkit asks polkit, which shows the user's own authentication dialog, to
// authorize dev.keylatch.privileged for the peer process as a unix-process
// subject (pid, start time, uid). The daemon runs pkcheck, which makes the same
// CheckAuthorization call with AllowUserInteraction over the system bus.
type Polkit struct {
	// Bin is the pkcheck executable. Its location is fixed: PATH belongs to the
	// caller, and a planted pkcheck would approve everything.
	Bin string
	// Run executes Bin with args; nil runs it for real.
	Run func(ctx context.Context, bin string, args ...string) error
}

// NewPolkit returns the polkit method when pkcheck is installed, and nil
// otherwise.
func NewPolkit() *Polkit {
	for _, p := range []string{"/usr/bin/pkcheck", "/bin/pkcheck"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return &Polkit{Bin: p}
		}
	}
	return nil
}

// Name implements PresenceMethod.
func (*Polkit) Name() string { return "polkit" }

// Verify implements PresenceMethod.
func (p *Polkit) Verify(ctx context.Context, s Subject, action, summary string) error {
	if s.PID <= 0 || s.Start == "" {
		return fmt.Errorf("%w: the peer cannot be named to polkit", ErrPresenceUnavailable)
	}
	args := []string{
		"--action-id", polkitAction,
		"--process", fmt.Sprintf("%d,%s,%d", s.PID, s.Start, s.UID),
		"--allow-user-interaction",
		"--detail", "keylatch.action", action,
		"--detail", "keylatch.summary", summary,
	}
	run := p.Run
	if run == nil {
		run = func(ctx context.Context, bin string, args ...string) error {
			return exec.CommandContext(ctx, bin, args...).Run() //nolint:gosec // G204: fixed binary, the arguments are numbers and daemon-built text
		}
	}
	if err := run(ctx, p.Bin, args...); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("polkit refused (exit %d)", exit.ExitCode())
		}
		return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	return nil
}

type proofRecord struct {
	uid     uint32
	digest  string
	method  string
	expires time.Time
}

// Proofs issues and spends presence proofs.
type Proofs struct {
	now func() time.Time

	mu sync.Mutex
	m  map[string]proofRecord
}

// NewProofs returns an empty proof table.
func NewProofs(now func() time.Time) *Proofs {
	if now == nil {
		now = time.Now
	}
	return &Proofs{now: now, m: map[string]proofRecord{}}
}

// Issue records a proof for uid and the request digest.
func (p *Proofs) Issue(uid uint32, digest, method string) brokerapi.Proof {
	var raw [brokerapi.ProofLen]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	exp := p.now().Add(ProofTTL)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, r := range p.m {
		if p.now().After(r.expires) {
			delete(p.m, k)
		}
	}
	p.m[id] = proofRecord{uid: uid, digest: digest, method: method, expires: exp}
	return brokerapi.Proof{ID: id, Digest: digest, Method: method, ExpiresAt: exp.Unix()}
}

// Consume spends the proof id for uid and the request digest. A proof is
// removed the first time it is presented, whether or not it matches, so a
// guessed or replayed proof is worth nothing.
func (p *Proofs) Consume(id string, uid uint32, digest string) error {
	if id == "" {
		return ErrPresenceRequired
	}
	p.mu.Lock()
	r, ok := p.m[id]
	delete(p.m, id)
	p.mu.Unlock()
	switch {
	case !ok:
		return ErrProofInvalid
	case p.now().After(r.expires):
		return ErrProofExpired
	case r.uid != uid || subtle.ConstantTimeCompare([]byte(r.digest), []byte(digest)) != 1:
		return ErrProofInvalid
	}
	return nil
}

// PromptTimeout bounds how long the daemon waits for the human to answer.
const PromptTimeout = 2 * time.Minute

// ErrPromptOpen means a presence prompt for this user is already waiting for an
// answer. One at a time keeps a process from burying the human in dialogs.
var ErrPromptOpen = errors.New("brokerd: a presence prompt is already open for this user")

// Presence is the daemon's own verification of human presence.
type Presence struct {
	Method PresenceMethod
	Proofs *Proofs
	Audit  audit.Emitter
	// Timeout overrides PromptTimeout.
	Timeout time.Duration

	mu   sync.Mutex
	open map[uint32]bool
}

func (p *Presence) claim(uid uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open[uid] {
		return false
	}
	if p.open == nil {
		p.open = map[uint32]bool{}
	}
	p.open[uid] = true
	return true
}

func (p *Presence) release(uid uint32) {
	p.mu.Lock()
	delete(p.open, uid)
	p.mu.Unlock()
}

// MethodName names the method, or "none" when the daemon cannot verify presence.
func (p *Presence) MethodName() string {
	if p == nil || p.Method == nil {
		return "none"
	}
	return p.Method.Name()
}

// Begin asks the human to approve target on behalf of the peer and, on
// approval, issues a proof for exactly that request. The sentence the human
// reads is built here from the request, not taken from the client.
func (p *Presence) Begin(ctx context.Context, s Subject, res callerkind.Result, target brokerapi.Request) (brokerapi.Proof, error) {
	action, summary := target.Describe()
	digest := target.Digest()
	record := func(result, reason string) {
		if p == nil || p.Audit == nil {
			return
		}
		outcome := audit.OutcomeOK
		if result != "approved" {
			outcome = audit.OutcomeDenied
		}
		extra := map[string]any{"operation": action, "method": p.MethodName(), "result": result, "digest": digest, "caller_kind": string(res.Kind)}
		if reason != "" {
			extra["reason"] = reason
		}
		_ = p.Audit.Emit(ctx, audit.Event{Action: audit.ActionPresenceDecision, Outcome: outcome, Extra: extra})
	}
	switch {
	case res.Kind == callerkind.Agent:
		record("refused", "agent session")
		return brokerapi.Proof{}, ErrAgentPresence
	case p == nil || p.Method == nil:
		record("unavailable", "no presence method")
		return brokerapi.Proof{}, ErrPresenceUnavailable
	}
	if !p.claim(s.UID) {
		record("refused", "a prompt is already open")
		return brokerapi.Proof{}, ErrPromptOpen
	}
	defer p.release(s.UID)
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = PromptTimeout
	}
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := p.Method.Verify(vctx, s, action, summary); err != nil {
		record("denied", err.Error())
		return brokerapi.Proof{}, err
	}
	record("approved", "")
	return p.Proofs.Issue(s.UID, digest, p.Method.Name()), nil
}

// Require checks that req carries a proof issued for it to uid.
func (p *Presence) Require(uid uint32, req brokerapi.Request) error {
	if p == nil || p.Proofs == nil {
		return ErrPresenceUnavailable
	}
	return p.Proofs.Consume(req.Proof, uid, req.Digest())
}

func subjectOf(pid int, start string, uid uint32) Subject {
	return Subject{PID: pid, Start: start, UID: uid}
}

func uidString(uid uint32) string { return strconv.FormatUint(uint64(uid), 10) }
