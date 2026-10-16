//go:build unix

package brokerd

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
)

var setReq = brokerapi.Request{Op: brokerapi.OpSecretSet, Path: "svc/key", Value: []byte("v")}

func TestPrivilegedRefusedWithoutProof(t *testing.T) {
	h := newHarness(t, nil)
	// Every privileged operation, sent as a raw request by a client that never
	// asked for presence, is refused, and nothing changes.
	for _, req := range []brokerapi.Request{
		setReq,
		{Op: brokerapi.OpSecretDelete, Path: "svc/key"},
		{Op: brokerapi.OpPolicyAccept, Files: map[string][]byte{"policy.json": []byte(`{}`)}},
		{Op: brokerapi.OpPolicyImport, Bundle: &brokerapi.Bundle{Files: map[string][]byte{"policy.json": []byte(`{}`)}}},
		{Op: brokerapi.OpMigrateImport, Nonce: make([]byte, 16)},
		{Op: brokerapi.OpMigrateExport},
		{Op: brokerapi.OpRotateKeys},
	} {
		resp := h.send(t, 1000, req)
		if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
			t.Errorf("%s without a proof = %+v", req.Op, resp)
		}
	}
	if list := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretList}); len(list.Entries) != 0 {
		t.Fatal("a refused request stored something")
	}
	if got := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPolicyCheck}).Policy.State; got != PolicyAbsent {
		t.Fatalf("policy state = %s after refused accepts", got)
	}
	if h.srv.cfg.Keys.Pending() {
		t.Fatal("a refused rotation staged a key")
	}

	// An agent is refused outright, even holding a valid proof for the request.
	req := h.proven(t, 1000, setReq)
	resp := h.sendAs(t, peerAs(1000, ""), callerkind.Result{Kind: callerkind.Agent, Reasons: []string{"signals"}}, req)
	if resp.OK || resp.Code != brokerapi.CodeRefused {
		t.Fatalf("agent with a proof = %+v", resp)
	}
	if h.rec.count(audit.ActionSecurityBlock) == 0 {
		t.Fatal("an agent's privileged request must leave a security.block event")
	}

	// With a proof it works.
	good := h.proven(t, 1000, setReq)
	if resp := h.send(t, 1000, good); !resp.OK {
		t.Fatalf("set with a proof = %+v", resp)
	}
}

func TestProofReplayRefused(t *testing.T) {
	h := newHarness(t, nil)
	req := h.proven(t, 1000, setReq)
	if resp := h.send(t, 1000, req); !resp.OK {
		t.Fatalf("first use = %+v", resp)
	}
	resp := h.send(t, 1000, req)
	if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("a replayed proof = %+v", resp)
	}
}

func TestProofBoundToDigest(t *testing.T) {
	h := newHarness(t, nil)

	// A proof for one value cannot store another, and is burned by the attempt.
	req := h.proven(t, 1000, setReq)
	other := req
	other.Value = []byte("something else")
	if resp := h.send(t, 1000, other); resp.OK {
		t.Fatalf("a proof moved to another value = %+v", resp)
	}
	if resp := h.send(t, 1000, req); resp.OK {
		t.Fatal("a mismatched attempt must burn the proof")
	}

	// A proof for one operation does not authorize another.
	req = h.proven(t, 1000, setReq)
	del := brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: setReq.Path, Proof: req.Proof}
	if resp := h.send(t, 1000, del); resp.OK {
		t.Fatalf("a set proof used for a delete = %+v", resp)
	}

	// A proof is for the user it was issued to.
	req = h.proven(t, 1000, setReq)
	if resp := h.send(t, 1001, req); resp.OK {
		t.Fatalf("a proof used by another user = %+v", resp)
	}

	// A proof expires.
	req = h.proven(t, 1000, setReq)
	*h.now = h.now.Add(ProofTTL + time.Second)
	if resp := h.send(t, 1000, req); resp.OK {
		t.Fatalf("an expired proof = %+v", resp)
	}

	// The digest the human approved is the digest of the request that runs.
	d := setReq.Digest()
	if proof := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq}).Proof; proof.Digest != d {
		t.Fatalf("proof digest %s, want %s", proof.Digest, d)
	}
}

func TestPresenceUnavailableAndDenied(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Presence = nil })
	resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if resp.OK || resp.Code != brokerapi.CodeUnavailable {
		t.Fatalf("no presence method = %+v", resp)
	}
	if st := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpStatus}).Status; st.Presence != "none" {
		t.Fatalf("status presence = %q", st.Presence)
	}

	h = newHarness(t, nil)
	h.pres.err = errors.New("polkit refused (exit 126)")
	resp = h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("a refusal by the human = %+v", resp)
	}
	if ev, _ := h.rec.last(audit.ActionPresenceDecision); ev.Extra["result"] != "denied" {
		t.Fatalf("presence decision = %+v", ev)
	}

	// An agent session cannot even ask.
	resp = h.sendAs(t, peerAs(1000, ""), callerkind.Result{Kind: callerkind.Agent}, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if resp.OK || resp.Code != brokerapi.CodeRefused || len(h.pres.subjects) != 1 {
		t.Fatalf("agent presence.begin = %+v (prompts shown: %d)", resp, len(h.pres.subjects))
	}
}

func TestPresenceSubjectIsThePeer(t *testing.T) {
	h := newHarness(t, nil)
	peer := control.Peer{UID: 1234, PID: 31337, Start: "777"}
	p, err := h.srv.partition(context.Background(), peer.UID)
	if err != nil {
		t.Fatal(err)
	}
	resp := (&admin{s: h.srv, p: p}).dispatch(context.Background(), peer, host, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if !resp.OK {
		t.Fatalf("presence.begin = %+v", resp)
	}
	if len(h.pres.subjects) != 1 || h.pres.subjects[0] != (Subject{PID: 31337, Start: "777", UID: 1234}) {
		t.Fatalf("presence was asked for %+v, want the peer", h.pres.subjects)
	}
	if h.pres.actions[0] != "secret.set" {
		t.Fatalf("action = %q", h.pres.actions[0])
	}
	if ev, _ := h.rec.last(audit.ActionPresenceDecision); ev.Extra["result"] != "approved" || ev.Extra["digest"] != setReq.Digest() {
		t.Fatalf("presence decision = %+v", ev)
	}
}

// blockingPresence waits until released or its context ends.
type blockingPresence struct {
	started chan struct{}
	release chan struct{}
}

func (*blockingPresence) Name() string { return "blocking" }

func (b *blockingPresence) Verify(ctx context.Context, _ Subject, _, _ string) error {
	b.started <- struct{}{}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPresencePromptsDoNotStackAndTimeOut(t *testing.T) {
	m := &blockingPresence{started: make(chan struct{}, 4), release: make(chan struct{})}
	h := newHarness(t, func(c *Config) { c.Presence = m })

	first := make(chan brokerapi.Response, 1)
	go func() {
		first <- h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	}()
	<-m.started

	// A second prompt for the same user while one waits is refused without asking again.
	second := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if second.OK || !strings.Contains(second.Error, "already open") || len(m.started) != 0 {
		t.Fatalf("second prompt = %+v (prompts started: %d)", second, len(m.started))
	}
	// Another user is not held up by it.
	other := make(chan brokerapi.Response, 1)
	go func() {
		other <- h.send(t, 1001, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	}()
	<-m.started

	close(m.release)
	if resp := <-first; !resp.OK {
		t.Fatalf("first prompt = %+v", resp)
	}
	if resp := <-other; !resp.OK {
		t.Fatalf("other user's prompt = %+v", resp)
	}

	// An unanswered prompt gives up, and the user can ask again.
	slow := &blockingPresence{started: make(chan struct{}, 1), release: make(chan struct{})}
	h.srv.presence.Method, h.srv.presence.Timeout = slow, 20*time.Millisecond
	resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq})
	if resp.OK {
		t.Fatalf("an unanswered prompt = %+v", resp)
	}
	close(slow.release)
	h.srv.presence.Method = &fakePresence{}
	if resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq}); !resp.OK {
		t.Fatalf("a prompt after a timeout = %+v", resp)
	}
}

func TestPolkitSubjectIsPeer(t *testing.T) {
	var gotBin string
	var gotArgs []string
	p := &Polkit{Bin: "/usr/bin/pkcheck", Run: func(_ context.Context, bin string, args ...string) error {
		gotBin, gotArgs = bin, args
		return nil
	}}
	err := p.Verify(context.Background(), Subject{PID: 31337, Start: "777", UID: 1234}, "secret.set", "Store a secret")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{
		"--action-id dev.keylatch.privileged",
		"--process 31337,777,1234",
		"--allow-user-interaction",
		"--detail keylatch.summary Store a secret",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("pkcheck args %q lack %q", joined, want)
		}
	}
	if gotBin != "/usr/bin/pkcheck" {
		t.Fatalf("bin = %q", gotBin)
	}
	if slices.Contains(gotArgs, "auth_self_keep") || strings.Contains(joined, "--enable-internal-agent") {
		t.Fatal("the check must not retain authorization or use an internal agent")
	}

	for _, bad := range []Subject{{PID: 0, Start: "1"}, {PID: 5, Start: ""}} {
		if err := p.Verify(context.Background(), bad, "a", "b"); !errors.Is(err, ErrPresenceUnavailable) {
			t.Fatalf("Verify(%+v) = %v, want ErrPresenceUnavailable", bad, err)
		}
	}
	p.Run = func(context.Context, string, ...string) error { return errors.New("boom") }
	if err := p.Verify(context.Background(), Subject{PID: 1, Start: "1"}, "a", "b"); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("a launch failure = %v, want ErrPresenceUnavailable", err)
	}
}

func TestPolkitRefusalExitCode(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 126")
	runErr := cmd.Run()
	p := &Polkit{Bin: "x", Run: func(context.Context, string, ...string) error { return runErr }}
	err := p.Verify(context.Background(), Subject{PID: 1, Start: "1"}, "a", "b")
	if err == nil || errors.Is(err, ErrPresenceUnavailable) || !strings.Contains(err.Error(), "126") {
		t.Fatalf("a polkit refusal = %v", err)
	}
	if NewPolkit() != nil && NewPolkit().Name() != "polkit" {
		t.Fatal("polkit method name")
	}
}

func TestProofsTable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := NewProofs(func() time.Time { return now })
	if err := p.Consume("", 1, "d"); !errors.Is(err, ErrPresenceRequired) {
		t.Fatalf("empty proof = %v", err)
	}
	if err := p.Consume("nope", 1, "d"); !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("unknown proof = %v", err)
	}
	a := p.Issue(1, "d", "polkit")
	now = now.Add(ProofTTL + time.Second)
	if err := p.Consume(a.ID, 1, "d"); !errors.Is(err, ErrProofExpired) {
		t.Fatalf("expired = %v", err)
	}
	b := p.Issue(1, "d", "polkit")
	if len(p.m) != 1 {
		t.Fatalf("expired proofs must be purged on issue, have %d", len(p.m))
	}
	if err := p.Consume(b.ID, 1, "d"); err != nil {
		t.Fatalf("fresh proof = %v", err)
	}
	var np *Presence
	if err := np.Require(1, setReq); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("nil presence Require = %v", err)
	}
	if np.MethodName() != "none" {
		t.Fatal("nil presence method name")
	}
}
