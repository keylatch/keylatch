//go:build unix

package brokerd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
)

var policyFiles = map[string][]byte{
	"policy.json":          []byte(`{"default_deny":true}`),
	"policy.d/github.json": []byte(`{"connection":"github"}`),
}

func acceptReq() brokerapi.Request {
	return brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: policyFiles}
}

func partitionConfig(t *testing.T, h *harness, uid uint32) string {
	t.Helper()
	return filepath.Join(h.srv.PartitionDir(uid), "config")
}

func state(t *testing.T, h *harness, uid uint32) brokerapi.PolicyState {
	t.Helper()
	return *h.send(t, uid, brokerapi.Request{Op: brokerapi.OpPolicyCheck}).Policy
}

func TestPolicySignedOnAccept(t *testing.T) {
	h := newHarness(t, nil)
	req := h.proven(t, 1000, acceptReq())
	resp := h.send(t, 1000, req)
	if !resp.OK || resp.Policy.State != PolicySigned {
		t.Fatalf("accept = %+v", resp)
	}
	if resp.Policy.PresenceHash != req.Digest() {
		t.Fatalf("the signature must record the presence digest %s, got %s", req.Digest(), resp.Policy.PresenceHash)
	}
	pub, err := h.srv.cfg.Keys.Public("policy-signing")
	if err != nil || resp.Policy.KeyID != keyIDOf(pub) {
		t.Fatalf("signed under key %s, want the policy-signing key (%v)", resp.Policy.KeyID, err)
	}
	cfg := partitionConfig(t, h, 1000)
	for name, want := range policyFiles {
		got, err := os.ReadFile(filepath.Join(cfg, filepath.FromSlash(name)))
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s = %q, %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg, sigFile)); err != nil {
		t.Fatalf("no signature file: %v", err)
	}
	if h.rec.count(audit.ActionPolicyChange) != 1 {
		t.Fatalf("policy.change events = %d", h.rec.count(audit.ActionPolicyChange))
	}

	// A second accept replaces the first, files included.
	next := brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: map[string][]byte{"policy.json": []byte(`{"default_deny":true,"rules":[]}`)}}
	next = h.proven(t, 1000, next)
	if resp := h.send(t, 1000, next); !resp.OK || resp.Policy.State != PolicySigned {
		t.Fatalf("second accept = %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(cfg, "policy.d", "github.json")); err == nil {
		t.Fatal("a file dropped from the policy must be removed")
	}

	// A policy the enforcer cannot load is refused, not signed.
	bad := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: map[string][]byte{"policy.json": []byte(`{"rules":[{"runtime":"bogus"}]}`)}})
	if resp := h.send(t, 1000, bad); resp.OK {
		t.Fatalf("a policy that does not load was accepted: %+v", resp)
	}
	notJSON := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: map[string][]byte{"policy.json": []byte(`{}`), "policy.d/x.json": []byte("nope")}})
	if resp := h.send(t, 1000, notJSON); resp.OK {
		t.Fatalf("a policy.d file that is not JSON was accepted: %+v", resp)
	}
	if st := state(t, h, 1000); st.State != PolicySigned {
		t.Fatalf("refused accepts must leave the old policy signed, got %s", st.State)
	}
}

func TestTamperedPolicyIgnored(t *testing.T) {
	h := newHarness(t, nil)
	if resp := h.send(t, 1000, h.proven(t, 1000, acceptReq())); !resp.OK {
		t.Fatal(resp.Error)
	}
	cfg := partitionConfig(t, h, 1000)
	gate := func() error {
		p, _ := h.srv.partition(context.Background(), 1000)
		return p.policy.Gate(context.Background(), host)
	}
	if err := gate(); err != nil {
		t.Fatalf("a signed policy must pass the gate: %v", err)
	}

	for name, tamper := range map[string]func(){
		"file edited as root": func() {
			if err := os.WriteFile(filepath.Join(cfg, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"file added to policy.d": func() {
			if err := os.WriteFile(filepath.Join(cfg, "policy.d", "extra.json"), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"file removed": func() {
			if err := os.Remove(filepath.Join(cfg, "policy.d", "github.json")); err != nil {
				t.Fatal(err)
			}
		},
		"signature deleted": func() {
			if err := os.Remove(filepath.Join(cfg, sigFile)); err != nil {
				t.Fatal(err)
			}
		},
		"signature forged": func() {
			b, _ := os.ReadFile(filepath.Join(cfg, sigFile))
			b = []byte(strings.Replace(string(b), `"signature":"`, `"signature":"AAAA`, 1))
			if err := os.WriteFile(filepath.Join(cfg, sigFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"signature garbage": func() {
			if err := os.WriteFile(filepath.Join(cfg, sigFile), []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Restore a signed policy, then break it.
			req := h.proven(t, 1000, acceptReq())
			if resp := h.send(t, 1000, req); !resp.OK {
				t.Fatal(resp.Error)
			}
			before := h.rec.count(audit.ActionSecurityBlock)
			tamper()
			st := state(t, h, 1000)
			if st.State != PolicyTampered && st.State != PolicyUnsigned {
				t.Fatalf("state = %s, want tampered or unsigned", st.State)
			}
			err := gate()
			if err == nil || !strings.Contains(err.Error(), "ignores it and denies") {
				t.Fatalf("the daemon must fall back to deny, got %v", err)
			}
			if h.rec.count(audit.ActionSecurityBlock) != before+1 {
				t.Fatal("the failure must be audited as security.block")
			}
			_ = gate() // a repeat of the same failure does not flood the log
			if h.rec.count(audit.ActionSecurityBlock) != before+1 {
				t.Fatal("a repeated failure must be audited once")
			}
			if _, err := h.srv.parts[1000].policy.Export(); err == nil {
				t.Fatal("a policy that does not verify must not be exported")
			}
		})
	}

	// Accepting again with presence recovers.
	if resp := h.send(t, 1000, h.proven(t, 1000, acceptReq())); !resp.OK || resp.Policy.State != PolicySigned {
		t.Fatalf("re-accept = %+v", resp)
	}
	if err := gate(); err != nil {
		t.Fatalf("gate after recovery: %v", err)
	}
}

func TestTamperedPolicyRefusesServedRequests(t *testing.T) {
	h := newHarness(t, nil)
	cfg := partitionConfig(t, h, 1000)
	if _, err := h.srv.partition(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.srv.cfg.Identify = func(*net.UnixConn) (*Identity, error) { return &Identity{UID: 1000, PID: 1, pin: okPin{}}, nil }
	call, stop := h.serve(t)
	defer stop()

	// A run request is gated by the broken policy and refused.
	var resp struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	call(map[string]any{"op": "run_session", "run": map[string]any{"connection": "x", "command": []string{"true"}}}, &resp)
	if resp.Code != "refused" || !strings.Contains(resp.Error, "denies") {
		t.Fatalf("run_session under a tampered policy = %+v", resp)
	}
	// Diagnostics stay available.
	var st brokerapi.Response
	call(brokerapi.Request{Op: brokerapi.OpStatus}, &st)
	if !st.OK || st.Status.Policy != PolicyUnsigned {
		t.Fatalf("status = %+v", st)
	}
}

func TestImportNeedsPresence(t *testing.T) {
	h := newHarness(t, nil)
	// A signed bundle from another host.
	other := newHarness(t, nil)
	if resp := other.send(t, 1000, other.proven(t, 1000, acceptReq())); !resp.OK {
		t.Fatal(resp.Error)
	}
	exp := other.send(t, 1000, brokerapi.Request{Op: brokerapi.OpPolicyExport})
	if !exp.OK || exp.Bundle == nil || len(exp.Bundle.Signature) == 0 || exp.Bundle.PresenceDigest == "" {
		t.Fatalf("export = %+v", exp)
	}

	imp := brokerapi.Request{Op: brokerapi.OpPolicyImport, Bundle: exp.Bundle}
	if resp := h.send(t, 1000, imp); resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("an import without presence = %+v", resp)
	}
	if st := state(t, h, 1000); st.State != PolicyAbsent {
		t.Fatalf("a refused import changed the policy: %s", st.State)
	}

	imp = h.proven(t, 1000, imp)
	resp := h.send(t, 1000, imp)
	if !resp.OK || resp.Policy.State != PolicySigned {
		t.Fatalf("import with presence = %+v", resp)
	}
	// The imported policy is signed by this daemon for this approval, not by the other host.
	if resp.Policy.PresenceHash != imp.Digest() || resp.Policy.KeyID == exp.Bundle.KeyID {
		t.Fatalf("imported policy state = %+v (origin key %s)", resp.Policy, exp.Bundle.KeyID)
	}
	if h.pres.actions[len(h.pres.actions)-1] != "policy.change" {
		t.Fatalf("the human was shown %q", h.pres.actions)
	}
}

func TestPolicyGateAbsentAndAuditless(t *testing.T) {
	h := newHarness(t, nil)
	p, _ := h.srv.partition(context.Background(), 1000)
	if err := p.policy.Gate(context.Background(), callerkind.Result{Kind: callerkind.Host}); err != nil {
		t.Fatalf("no policy at all is not tampering: %v", err)
	}
	if got := p.policy.Names(); len(got) != 0 {
		t.Fatalf("Names = %v", got)
	}
	p.policy.Audit = nil
	if err := os.WriteFile(filepath.Join(p.policy.Dir, "policy.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.policy.Gate(context.Background(), host); err == nil {
		t.Fatal("an unsigned policy must be refused even without an audit emitter")
	}
	if got := p.policy.Names(); len(got) != 1 {
		t.Fatalf("Names = %v", got)
	}
}
