//go:build unix

package brokerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/presence"
)

func controlKeyRequest(t *testing.T, p *partition, peer control.Peer, req control.Request) control.Response {
	t.Helper()
	server, client := pair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.ctl.ServeConn(t.Context(), server, peer)
	}()
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatal(err)
	}
	var response control.Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	<-done
	return response
}

func TestBrokerKeyPolicyUsesPeerAndPartition(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.srv.partition(t.Context(), 1001)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Put(t.Context(), "keys/sign", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	allow := control.Request{Op: control.OpKeyPolicy, KeyPolicy: &control.KeyPolicyRequest{
		Action: "allow", Connection: "app", Field: "SIGN", Secret: "keys/sign", Operations: []string{"sign"}, Algorithms: []string{"HS256"},
	}}
	if resp := controlKeyRequest(t, p, peerAs(1000, ""), allow); !resp.OK {
		t.Fatalf("allow: %+v", resp)
	}
	if len(h.pres.subjects) != 1 || h.pres.subjects[0] != (Subject{UID: 1000, PID: 4242, Start: "9999"}) {
		t.Fatalf("wrong authenticated subject: %v", h.pres.subjects)
	}
	sign := control.Request{Op: control.OpKey, Key: &control.KeyRequest{Action: "sign", Connection: "app", Field: "SIGN", Alg: "HS256", Input: []byte("message")}}
	if resp := controlKeyRequest(t, p, peerAs(1000, ""), sign); !resp.OK || len(resp.Stdout) == 0 {
		t.Fatalf("sign: %+v", resp)
	}
	if resp := controlKeyRequest(t, other, peerAs(1001, ""), sign); resp.OK {
		t.Fatal("another partition used the allowlist")
	}
	if resp := controlKeyRequest(t, other, peerAs(1000, ""), allow); resp.OK {
		t.Fatal("cross-UID presence accepted")
	}
	sealed, err := os.ReadFile(paths.KeyOperations(p.env))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.KeyOperations(other.env), sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := controlKeyRequest(t, other, peerAs(1001, ""), sign); resp.OK {
		t.Fatal("copied policy verified in another partition")
	}
	if err := os.WriteFile(filepath.Join(p.policy.Dir, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := controlKeyRequest(t, p, peerAs(1000, ""), sign); resp.OK {
		t.Fatal("unsigned policy bypassed the policy gate")
	}
}

func TestBrokerKeyPolicyFailsClosed(t *testing.T) {
	for _, why := range []string{"unavailable", "denied", "peer exited", "agent"} {
		t.Run(why, func(t *testing.T) {
			h := newHarness(t, nil)
			p, err := h.srv.partition(t.Context(), 1000)
			if err != nil {
				t.Fatal(err)
			}
			peer := peerAs(1000, "")
			switch why {
			case "agent":
				h.srv.callers.Chain = func(int) []llmcontext.Process { return []llmcontext.Process{{PID: 4242, Names: []string{"claude"}}} }
			case "unavailable":
				h.srv.presence.Method = nil
			case "denied":
				h.pres.err = presence.ErrDenied
			case "peer exited":
				calls := 0
				peer.Verify = func() error {
					calls++
					if calls > 1 {
						return errors.New("peer exited")
					}
					return nil
				}
			}
			resp := controlKeyRequest(t, p, peer, control.Request{Op: control.OpKeyPolicy, KeyPolicy: &control.KeyPolicyRequest{
				Action: "allow", Connection: "app", Field: "SIGN", Secret: "keys/sign", Operations: []string{"sign"}, PresenceDigest: "forged",
			}})
			if resp.OK {
				t.Fatalf("accepted %s", why)
			}
			if why == "agent" && len(h.pres.subjects) != 0 {
				t.Fatal("agent triggered a presence prompt")
			}
			if _, err := os.Stat(paths.KeyOperations(p.env)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unauthorized policy published: %v", err)
			}
		})
	}
}

func TestBrokerKeyPresenceRejectsWrongSubject(t *testing.T) {
	h := newHarness(t, nil)
	for _, peer := range []control.Peer{{UID: 1001, PID: 2, Start: "3"}, {UID: 1000}, {UID: 1000, PID: 2}} {
		if err := h.srv.keyPresence(1000)(context.Background(), peer, presence.ActionKeyAllow, "summary"); err == nil {
			t.Fatal("invalid subject accepted")
		}
	}
	if len(h.pres.subjects) != 0 {
		t.Fatal("invalid subject prompted")
	}
	keyA, err := h.srv.cfg.Keys.KeyPolicyKeyFor("1000")
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := h.srv.cfg.Keys.TokenKeyFor("1000")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("policy and token keys share a domain")
	}
	clear(keyA)
	clear(keyB)
}
