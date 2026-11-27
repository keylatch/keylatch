//go:build unix

package brokerd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/paths"
)

type approvalPrompt func(context.Context, Subject, string, string) error

func TestApprovalHandlerCompletesWithClientConnected(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	dir := paths.ApprovalsDir(p.env)
	ar, err := approval.RequestNewPlan(t.Context(), dir, "agent", "run:D5", "app", "hash", "argv: [\"safe\"]", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server, client := connPair()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: ar.Token, Digest: approval.Digest(ar), Decision: "approve"}}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&admin{s: h.srv, p: p}).Handle(t.Context(), server, peerAs(1000, ""), host, raw)
	}()
	var response brokerapi.Response
	if err := json.NewDecoder(client).Decode(&response); err != nil || !response.OK {
		t.Fatalf("approval response: %+v, %v", response, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("approval handler did not stop its disconnect monitor")
	}
	current, err := approval.Get(t.Context(), dir, ar.Token)
	if err != nil || current.Status != approval.StatusApproved || current.PresenceDigest == "" {
		t.Fatalf("approval was not signed: %+v, %v", current, err)
	}
}

func TestApprovalDisconnectCancelsPromptWithoutSigning(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	dir := paths.ApprovalsDir(p.env)
	ar, err := approval.RequestNewPlan(t.Context(), dir, "agent", "run:D5", "app", "hash", "argv: [\"safe\"]", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	h.srv.presence.Method = approvalPrompt(func(ctx context.Context, _ Subject, _, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	server, client := connPair()
	defer server.Close()
	defer client.Close()
	req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: ar.Token, Digest: approval.Digest(ar), Decision: "approve"}}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&admin{s: h.srv, p: p}).Handle(t.Context(), server, peerAs(1000, ""), host, raw)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("approval prompt did not start")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("disconnected approval still waits for presence")
	}
	current, err := approval.Get(t.Context(), dir, ar.Token)
	if err != nil || current.Status != approval.StatusPending || current.PresenceDigest != "" {
		t.Fatalf("disconnected approval changed: %+v, %v", current, err)
	}
}

func (approvalPrompt) Name() string { return "test-os" }
func (p approvalPrompt) Verify(ctx context.Context, subject Subject, action, summary string) error {
	return p(ctx, subject, action, summary)
}

func TestBrokerApprovalSignsExactRequestForOneUser(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	dir := paths.ApprovalsDir(p.env)
	ar, err := approval.RequestNewPlan(t.Context(), dir, "agent", "run:D5", "app", "request-hash", "argv: [\"deploy\"]\nhosts: [\"example.test\"]\nTTL: 1m", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	list := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpApprovalList})
	if !list.OK || len(list.Approvals) != 1 || list.Approvals[0].Digest != approval.Digest(ar) || !strings.Contains(list.Approvals[0].Summary, "example.test") {
		t.Fatalf("list: %+v", list)
	}
	if other := h.send(t, 1001, brokerapi.Request{Op: brokerapi.OpApprovalList}); !other.OK || len(other.Approvals) != 0 {
		t.Fatalf("cross-user list: %+v", other)
	}
	h.srv.presence.Method = approvalPrompt(func(_ context.Context, subject Subject, action, summary string) error {
		if subject.UID != 1000 || subject.PID != 4242 || action != "run.approve" || summary != approval.Summary(ar) {
			t.Fatalf("wrong presence request: %+v %s %s", subject, action, summary)
		}
		return nil
	})
	req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: ar.Token, Digest: list.Approvals[0].Digest, Decision: "approve"}}
	if resp := h.send(t, 1000, req); !resp.OK {
		t.Fatalf("decision: %+v", resp)
	}
	decided, err := approval.Get(t.Context(), dir, ar.Token)
	if err != nil || decided.PresenceMethod != "test-os" || decided.PresenceDigest == "" {
		t.Fatalf("presence record: %+v %v", decided, err)
	}
	otherKey, err := h.srv.cfg.Keys.ApprovalSignerFor("1001")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(otherKey)
	if err := approval.Verify(t.Context(), dir, ar.Token, ar.RequestHash, otherKey.Public().(ed25519.PublicKey)); !errors.Is(err, approval.ErrUnsigned) {
		t.Fatalf("cross-user signature: %v", err)
	}
	key, err := h.srv.cfg.Keys.ApprovalSignerFor("1000")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if err := approval.Verify(t.Context(), dir, ar.Token, ar.RequestHash, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := approval.Verify(t.Context(), dir, ar.Token, ar.RequestHash, key.Public().(ed25519.PublicKey)); !errors.Is(err, approval.ErrUsed) {
		t.Fatalf("approval replay accepted: %v", err)
	}
}

func TestBrokerApprovalFailureDoesNotSign(t *testing.T) {
	for _, why := range []string{"agent", "changed digest", "other user", "unavailable", "denied", "changed during prompt", "peer exited", "audit failed"} {
		t.Run(why, func(t *testing.T) {
			h := newHarness(t, nil)
			p, err := h.srv.partition(t.Context(), 1000)
			if err != nil {
				t.Fatal(err)
			}
			dir := paths.ApprovalsDir(p.env)
			ar, err := approval.RequestNewPlan(t.Context(), dir, "agent", "run:D5", "app", "hash", "argv: [\"safe\"]", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: ar.Token, Digest: approval.Digest(ar), Decision: "approve"}}
			peer, res := peerAs(1000, ""), host
			switch why {
			case "agent":
				res.Kind = callerkind.Agent
			case "changed digest":
				req.Approval.Digest = strings.Repeat("0", 64)
			case "other user":
				peer.UID = 1001
			case "unavailable":
				h.srv.presence.Method = nil
			case "denied":
				h.pres.err = errors.New("denied")
			case "audit failed":
				h.rec.fail = errors.New("audit unavailable")
			case "peer exited":
				checks := 0
				peer.Verify = func() error {
					checks++
					if checks > 1 {
						return ErrPeerGone
					}
					return nil
				}
			case "changed during prompt":
				h.srv.presence.Method = approvalPrompt(func(context.Context, Subject, string, string) error {
					ar.Plan = "argv: [\"different\"]"
					data, err := json.Marshal(ar)
					if err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(dir, ar.Token+".json"), data, 0o600)
				})
			}
			if response := h.sendAs(t, peer, res, req); response.OK {
				t.Fatalf("accepted %s", why)
			}
			current, err := approval.Get(t.Context(), dir, ar.Token)
			if err != nil || current.Signature != "" || current.Status != approval.StatusPending {
				t.Fatalf("failed request signed: %+v %v", current, err)
			}
			if (why == "agent" || why == "changed digest" || why == "other user") && len(h.pres.subjects) != 0 {
				t.Fatal("invalid request opened native prompt")
			}
		})
	}
}

func TestBrokerRunApproverConsumesDesktopDecision(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	notified := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := h.srv.approver(p)(ctx, control.ApprovalRequest{Connection: "app", Tier: control.TierContained, Caller: control.KindAgent, Argv: []string{"deploy", "--dry-run"}, Hosts: []string{"example.test"}, TTL: time.Minute, Notify: func(token string) { notified <- token }})
		done <- err
	}()
	select {
	case <-notified:
	case <-ctx.Done():
		t.Fatal("no approval request")
	}
	list := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpApprovalList})
	if !list.OK || len(list.Approvals) != 1 {
		t.Fatalf("list: %+v", list)
	}
	entry := list.Approvals[0]
	response := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: entry.Token, Digest: entry.Digest, Decision: "approve"}})
	if !response.OK {
		t.Fatalf("decision: %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
