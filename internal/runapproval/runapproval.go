// Package runapproval obtains the human approval a contained run or a binding
// change needs. A run's approval is a signed decision on a request that carries
// the exact plan; it is bound to the argv digest, the tier, the host set, the
// lifetime, the caller and the project, so an approval for one plan cannot
// start another, and it allows one start. A binding change is bound to the
// exact before and after host sets.
package runapproval

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// Errors a run waits on.
var (
	ErrNoApprover = errors.New("no approver passphrase is set; run `keylatch approve init` in a terminal")
	ErrDenied     = errors.New("the approval was denied")
	ErrTimeout    = errors.New("nobody approved the run in time")
)

// Plan is everything one approval of a contained run is bound to.
type Plan struct {
	Connection string
	Tier       string
	Caller     string
	Project    string
	Argv       []string
	Hosts      []string
	TTL        time.Duration
}

// ArgvDigest is the SHA-256 of the argument vector.
func (p Plan) ArgvDigest() string { return digest(p.Argv...) }

// Hash binds an approval to the plan: the connection, tier, caller, project,
// the argv digest, the sorted host set and the lifetime. Changing any of them
// changes the hash, and a decision on another hash does not apply.
func (p Plan) Hash() string {
	hosts := slices.Clone(p.Hosts)
	slices.Sort(hosts)
	return digest("keylatch/run-plan/v1", p.Connection, p.Tier, p.Caller, p.Project, p.ArgvDigest(), digest(hosts...), p.TTL.String())
}

// Text is the plan as the human reads it: every word of the command, the
// tier, the hosts, the project and the lifetime, with command controls visibly
// escaped so executable bytes cannot disappear from the review.
func (p Plan) Text() string {
	hosts := slices.Clone(p.Hosts)
	slices.Sort(hosts)
	var b strings.Builder
	fmt.Fprintf(&b, "run for a %s caller, tier %s, connection %s\n", clean(p.Caller), clean(p.Tier), clean(p.Connection))
	fmt.Fprintf(&b, "  command:  %s\n", quote(p.Argv))
	fmt.Fprintf(&b, "  project:  %+q (read-write)\n", p.Project)
	fmt.Fprintf(&b, "  network:  %s\n", orNone(hosts))
	fmt.Fprintf(&b, "  lifetime: %s\n", p.TTL)
	fmt.Fprintf(&b, "  argv sha256: %s\n", p.ArgvDigest())
	return b.String()
}

// BindingSummary is what a human approves when a connection's binding is
// created or widened: the exact host sets before and after.
func BindingSummary(connection, kind string, before, after []string) string {
	before, after = sorted(before), sorted(after)
	return fmt.Sprintf("%s the binding of %s\n  hosts before: %s\n  hosts after:  %s\n  added:   %s\n  removed: %s",
		clean(kind), clean(connection), orNone(before), orNone(after), orNone(difference(after, before)), orNone(difference(before, after)))
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func difference(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func orNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(in, ", ")
}

func quote(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = fmt.Sprintf("%+q", a)
	}
	return strings.Join(parts, " ")
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e || r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x2069 {
			return -1
		}
		return r
	}, s)
}

// digest hashes the parts with their lengths, so no two part lists collide.
func digest(parts ...string) string {
	h := sha256.New()
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Approver asks a human for the approval of a run and waits for it.
type Approver struct {
	// Dir is the approvals directory the `keylatch approve` command reads.
	Dir string
	// PublicKey returns the approver key decisions must be signed with.
	PublicKey func() (ed25519.PublicKey, error)
	// Wait is how long a request stays open; Poll how often it is looked at.
	Wait, Poll time.Duration
	// Audit receives approval.requested, approval.granted and approval.denied.
	Audit audit.Emitter
	// Sleep waits between looks; nil sleeps for real.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (a *Approver) emit(ctx context.Context, action audit.Action, outcome audit.Outcome, token string, p Plan, reason string) {
	if a.Audit == nil {
		return
	}
	extra := map[string]any{"approval_id": token, "connection": p.Connection, "tier": p.Tier, "caller_kind": p.Caller}
	if reason != "" {
		extra["reason"] = reason
	}
	_ = a.Audit.Emit(ctx, audit.Event{Action: action, Outcome: outcome, Extra: extra})
}

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Approve opens a request for the plan, tells notify how to answer it and
// waits for a signed decision. It returns the approval's token once a decision
// that approves exactly this plan has been verified and spent.
func (a *Approver) Approve(ctx context.Context, p Plan, notify func(string)) (string, error) {
	pub, err := a.PublicKey()
	if err != nil {
		if errors.Is(err, approval.ErrNoApproverKey) {
			return "", ErrNoApprover
		}
		return "", fmt.Errorf("approver key: %w", err)
	}
	wait := a.Wait
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	poll := a.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	sleep := a.Sleep
	if sleep == nil {
		sleep = realSleep
	}
	hash := p.Hash()
	ar, err := approval.RequestNewPlan(ctx, a.Dir, "daemon:"+p.Caller, "run:"+p.Tier, p.Connection, hash, p.Text(), wait)
	if err != nil {
		return "", err
	}
	a.emit(ctx, audit.ActionApprovalRequested, audit.OutcomeOK, ar.Token, p, "")
	if notify != nil {
		notify(fmt.Sprintf("keylatch: waiting for approval; run `keylatch approve %s` in your terminal\n", ar.Token))
	}

	deadline := time.Now().Add(wait)
	for {
		cur, err := approval.Get(ctx, a.Dir, ar.Token)
		if err != nil {
			a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeError, ar.Token, p, "request unreadable")
			return "", fmt.Errorf("read the approval: %w", err)
		}
		switch cur.Status {
		case approval.StatusApproved:
			if err := approval.Verify(ctx, a.Dir, ar.Token, hash, pub); err != nil {
				a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeDenied, ar.Token, p, "decision does not verify")
				return "", fmt.Errorf("the decision does not verify: %w", err)
			}
			a.emit(ctx, audit.ActionApprovalGranted, audit.OutcomeOK, ar.Token, p, "")
			return ar.Token, nil
		case approval.StatusDenied:
			a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeDenied, ar.Token, p, "denied")
			return "", ErrDenied
		case approval.StatusExpired:
			a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeDenied, ar.Token, p, "expired")
			return "", ErrTimeout
		}
		if !time.Now().Before(deadline) {
			a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeDenied, ar.Token, p, "timeout")
			return "", ErrTimeout
		}
		if err := sleep(ctx, poll); err != nil {
			a.emit(ctx, audit.ActionApprovalDenied, audit.OutcomeError, ar.Token, p, "cancelled")
			return "", err
		}
	}
}
