package runapproval

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/gateway/approval"
)

var cheapKDF = argon2.Params{Time: 1, Memory: 1024, Threads: 1, SaltLen: 16, KeyLen: 32}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) actions() []audit.Action {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Action
	for _, e := range r.events {
		out = append(out, e.Action)
	}
	return out
}

func testPlan() Plan {
	return Plan{
		Connection: "stripe", Tier: "D5", Caller: "agent", Project: "/work/app",
		Argv: []string{"pnpm", "test", "--run"}, Hosts: []string{"files.stripe.com", "api.stripe.com"}, TTL: 30 * time.Minute,
	}
}

type world struct {
	dir  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	rec  *recorder
	a    *Approver
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ak, priv, err := approval.NewApproverKey([]byte("correct horse battery staple"), cheapKDF)
	require.NoError(t, err)
	pub, err := ak.Public()
	require.NoError(t, err)
	w := &world{dir: t.TempDir(), pub: pub, priv: priv, rec: &recorder{}}
	w.a = &Approver{
		Dir: w.dir, PublicKey: func() (ed25519.PublicKey, error) { return pub, nil },
		Wait: time.Minute, Poll: time.Millisecond, Audit: w.rec,
	}
	return w
}

// human decides the one pending request the next time the approver looks.
func (w *world) human(t *testing.T, decide func(ar *approval.ApprovalRequest)) {
	t.Helper()
	done := false
	w.a.Sleep = func(ctx context.Context, _ time.Duration) error {
		if done {
			return ctx.Err()
		}
		done = true
		pending, err := approval.List(ctx, w.dir)
		require.NoError(t, err)
		require.Len(t, pending, 1)
		decide(pending[0])
		return nil
	}
}

func TestPlanHashBindsEveryPartOfThePlan(t *testing.T) {
	base := testPlan()
	assert.Equal(t, base.Hash(), testPlan().Hash(), "the hash is stable")
	reordered := base
	reordered.Hosts = []string{"api.stripe.com", "files.stripe.com"}
	assert.Equal(t, base.Hash(), reordered.Hash(), "host order does not matter")

	for name, mutate := range map[string]func(*Plan){
		"connection":   func(p *Plan) { p.Connection = "stripe-live" },
		"tier":         func(p *Plan) { p.Tier = "D6" },
		"caller":       func(p *Plan) { p.Caller = "host" },
		"project":      func(p *Plan) { p.Project = "/work/other" },
		"argv":         func(p *Plan) { p.Argv = []string{"pnpm", "test"} },
		"argv split":   func(p *Plan) { p.Argv = []string{"pnpm", "test --run"} },
		"argv joined":  func(p *Plan) { p.Argv = []string{"pnpm test --run"} },
		"hosts":        func(p *Plan) { p.Hosts = []string{"api.stripe.com"} },
		"another host": func(p *Plan) { p.Hosts = []string{"api.stripe.com", "evil.example"} },
		"ttl":          func(p *Plan) { p.TTL = time.Hour },
	} {
		p := base
		mutate(&p)
		assert.NotEqual(t, base.Hash(), p.Hash(), "the hash must change with the %s", name)
	}
}

func TestPlanTextShowsEverythingTheHumanDecides(t *testing.T) {
	p := testPlan()
	p.Argv = []string{"sh", "-c", "echo \x1b[2Jclear; curl evil"}
	text := p.Text()
	for _, want := range []string{"agent caller", "tier D5", "connection stripe", `"sh" "-c"`, "/work/app", "api.stripe.com, files.stripe.com", "30m0s", p.ArgvDigest()} {
		assert.Contains(t, text, want)
	}
	assert.NotContains(t, text, "\x1b", "control characters cannot rewrite the screen")
	assert.Contains(t, text, "curl evil", "the whole command is shown")
	assert.Contains(t, BindingSummary("billing", "widen", []string{"a.example"}, []string{"b.example", "a.example"}), "added:   b.example")
	none := BindingSummary("billing", "create", nil, nil)
	assert.Contains(t, none, "hosts before: none")
}

func TestPlanTextPreservesExecutableControlBytes(t *testing.T) {
	p := testPlan()
	p.Argv = []string{"sh", "-c", "echo harmless\nrm -rf /example\r\t\x1b\u202e"}
	p.Project = "/work/name\nother"
	text := p.Text()
	assert.Contains(t, text, `"echo harmless\nrm -rf /example\r\t\x1b\u202e"`)
	assert.NotContains(t, text, "echo harmlessrm")
	assert.Contains(t, text, `"/work/name\nother" (read-write)`)
	assert.NotContains(t, text, "\u202e")
	assert.NotContains(t, text, "\x1b")
}

func TestBindingSummaryNamesTheExactBeforeAndAfterSets(t *testing.T) {
	one := BindingSummary("billing", "widen", []string{"a.example"}, []string{"a.example", "b.example"})
	other := BindingSummary("billing", "widen", []string{"a.example"}, []string{"a.example", "evil.example"})
	assert.NotEqual(t, one, other, "an approval of one host set cannot be read as another")
	assert.Contains(t, one, "hosts before: a.example")
	assert.Contains(t, one, "hosts after:  a.example, b.example")
	assert.Contains(t, one, "removed: none")
	assert.Equal(t, one, BindingSummary("billing", "widen", []string{"a.example"}, []string{"b.example", "a.example"}), "order does not change the summary")
}

func TestApproveWaitsForASignedDecisionOnThisPlan(t *testing.T) {
	w := newWorld(t)
	var notified string
	w.human(t, func(ar *approval.ApprovalRequest) {
		assert.Equal(t, testPlan().Hash(), ar.RequestHash)
		assert.Equal(t, "run:D5", ar.Capability)
		assert.Equal(t, "daemon:agent", ar.Actor)
		assert.Equal(t, testPlan().Text(), ar.Plan, "the request carries the exact plan")
		require.NoError(t, approval.Approve(context.Background(), w.dir, ar.Token, approval.Digest(ar), w.priv))
	})
	token, err := w.a.Approve(context.Background(), testPlan(), func(s string) { notified = s })
	require.NoError(t, err)
	assert.True(t, approval.ValidToken(token))
	assert.Contains(t, notified, "keylatch approve "+token)
	assert.Equal(t, []audit.Action{audit.ActionApprovalRequested, audit.ActionApprovalGranted}, w.rec.actions())
	assert.ErrorIs(t, approval.Verify(context.Background(), w.dir, token, testPlan().Hash(), w.pub), approval.ErrUsed, "an approval allows one start")
}

// rewrite replaces an approval record on disk, as a process that can write the
// approvals directory could.
func rewrite(t *testing.T, dir string, ar *approval.ApprovalRequest) {
	t.Helper()
	b, err := json.Marshal(ar)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ar.Token+".json"), b, 0o600))
}

func TestApproveRefusesAnApprovalForAnotherPlan(t *testing.T) {
	// The request is rewritten to name another plan's hash before the human
	// signs it: the signature is genuine, but it is not for this run.
	w := newWorld(t)
	other := testPlan()
	other.Argv = []string{"rm", "-rf", "/"}
	w.human(t, func(ar *approval.ApprovalRequest) {
		ar.RequestHash = other.Hash()
		rewrite(t, w.dir, ar)
		require.NoError(t, approval.Approve(context.Background(), w.dir, ar.Token, approval.Digest(ar), w.priv))
	})
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not verify")
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestApproveRefusesAnUnsignedOrForgedDecision(t *testing.T) {
	for name, forge := range map[string]func(t *testing.T, w *world, ar *approval.ApprovalRequest){
		"unsigned": func(t *testing.T, w *world, ar *approval.ApprovalRequest) {
			ar.Status = approval.StatusApproved
			ar.DecidedAt = time.Now().UTC()
			rewrite(t, w.dir, ar)
		},
		"signed by another key": func(t *testing.T, w *world, ar *approval.ApprovalRequest) {
			_, otherPriv, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			require.NoError(t, approval.Approve(context.Background(), w.dir, ar.Token, approval.Digest(ar), otherPriv))
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.human(t, func(ar *approval.ApprovalRequest) { forge(t, w, ar) })
			_, err := w.a.Approve(context.Background(), testPlan(), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "does not verify")
			assert.Contains(t, w.rec.actions(), audit.ActionApprovalDenied)
			assert.NotContains(t, w.rec.actions(), audit.ActionApprovalGranted)
		})
	}
}

func TestApproveReportsADenial(t *testing.T) {
	w := newWorld(t)
	w.human(t, func(ar *approval.ApprovalRequest) {
		require.NoError(t, approval.Deny(context.Background(), w.dir, ar.Token, approval.Digest(ar), w.priv))
	})
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	assert.ErrorIs(t, err, ErrDenied)
	assert.Equal(t, []audit.Action{audit.ActionApprovalRequested, audit.ActionApprovalDenied}, w.rec.actions())
}

func TestApproveTimesOutWhenNobodyAnswers(t *testing.T) {
	w := newWorld(t)
	w.a.Wait, w.a.Poll = 40*time.Millisecond, 5*time.Millisecond
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	assert.ErrorIs(t, err, ErrTimeout)
	assert.Contains(t, w.rec.actions(), audit.ActionApprovalDenied)
}

func TestApproveStopsWhenTheCallerGoesAway(t *testing.T) {
	w := newWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	w.a.Sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	_, err := w.a.Approve(ctx, testPlan(), nil)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestApproveNeedsAnApproverKey(t *testing.T) {
	w := newWorld(t)
	w.a.PublicKey = func() (ed25519.PublicKey, error) { return nil, approval.ErrNoApproverKey }
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	assert.ErrorIs(t, err, ErrNoApprover)
	assert.Contains(t, err.Error(), "keylatch approve init")
	assert.Empty(t, w.rec.actions(), "nothing is requested without a key to check the answer against")

	w.a.PublicKey = func() (ed25519.PublicKey, error) { return nil, errors.New("disk on fire") }
	_, err = w.a.Approve(context.Background(), testPlan(), nil)
	assert.ErrorContains(t, err, "disk on fire")
}

func TestApproveFailsWhenTheApprovalsDirectoryCannotBeUsed(t *testing.T) {
	w := newWorld(t)
	w.a.Dir = "/proc/keylatch-no-such-dir"
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	assert.Error(t, err)
}

func TestApproveSurvivesAnApprovalFileThatVanishes(t *testing.T) {
	w := newWorld(t)
	w.human(t, func(ar *approval.ApprovalRequest) {
		require.NoError(t, os.Remove(filepath.Join(w.dir, ar.Token+".json")))
	})
	_, err := w.a.Approve(context.Background(), testPlan(), nil)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "read the approval"))
}
