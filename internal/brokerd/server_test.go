//go:build unix

package brokerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/control"
)

func setSecret(t *testing.T, h *harness, uid uint32, path, value string) {
	t.Helper()
	req := h.proven(t, uid, brokerapi.Request{Op: brokerapi.OpSecretSet, Path: path, Value: []byte(value)})
	if resp := h.send(t, uid, req); !resp.OK {
		t.Fatalf("set %s: %+v", path, resp)
	}
}

func TestPeerUIDPartitioning(t *testing.T) {
	h := newHarness(t, nil)
	setSecret(t, h, 1000, "svc/key", "alice-secret")

	// User B sees nothing of A, and a same-named secret is its own.
	if list := h.send(t, 1001, brokerapi.Request{Op: brokerapi.OpSecretList}); len(list.Entries) != 0 {
		t.Fatalf("user B lists %v", list.Entries)
	}
	setSecret(t, h, 1001, "svc/key", "bob-secret")
	for uid, want := range map[uint32]string{1000: "alice-secret", 1001: "bob-secret"} {
		p, _ := h.srv.partition(context.Background(), uid)
		got, _, err := p.store.Get(context.Background(), "svc/key")
		if err != nil || string(got) != want {
			t.Fatalf("user %d reads %q, %v", uid, got, err)
		}
	}

	// Each user's directory holds only that user's files, and is private.
	a, b := h.srv.PartitionDir(1000), h.srv.PartitionDir(1001)
	if a == b || filepath.Dir(a) != filepath.Dir(b) || filepath.Base(a) != "1000" {
		t.Fatalf("partition dirs %s, %s", a, b)
	}
	for _, d := range []string{a, b, filepath.Join(a, "config"), filepath.Join(a, "store")} {
		if info, err := os.Stat(d); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, info, err)
		}
	}
	for _, other := range []string{"alice-secret"} {
		_ = filepath.WalkDir(b, func(p string, d os.DirEntry, _ error) error {
			if !d.IsDir() {
				if body, _ := os.ReadFile(p); bytes.Contains(body, []byte(other)) {
					t.Errorf("%s holds another user's plaintext", p)
				}
			}
			return nil
		})
	}

	// A record of A's copied into B's store does not open there.
	src := filepath.Join(a, "store")
	files, _ := os.ReadDir(src)
	body, _ := os.ReadFile(filepath.Join(src, files[0].Name()))
	stolen := filepath.Join(b, "store", "stolen.json")
	if err := os.WriteFile(stolen, body, 0o600); err != nil {
		t.Fatal(err)
	}
	pb, _ := h.srv.partition(context.Background(), 1001)
	if entries, _ := pb.store.List(context.Background(), ""); len(entries) != 2 {
		t.Fatalf("B's store lists %d records", len(entries))
	}

	// The control server of each partition runs verbs against that partition only.
	if h.srv.parts[1000].ctl == h.srv.parts[1001].ctl {
		t.Fatal("partitions share a control server")
	}
}

func TestPartitionAdmission(t *testing.T) {
	h := newHarness(t, nil)
	h.srv.cfg.Identify = func(control.Conn) (*Identity, error) { return &Identity{UID: 0, PID: 1, pin: okPin{}}, nil }
	call, stop := h.serve(t)
	defer stop()

	var resp control.Response
	call(brokerapi.Request{Op: brokerapi.OpStatus}, &resp)
	if resp.Code != control.CodeRefused || !strings.Contains(resp.Error, "may not use the broker") {
		t.Fatalf("root = %+v", resp)
	}
	if _, err := os.Stat(h.srv.PartitionDir(0)); err == nil {
		t.Fatal("a refused user got a partition")
	}

	h.srv.cfg.Identify = func(control.Conn) (*Identity, error) { return nil, ErrNoPID }
	call(brokerapi.Request{Op: brokerapi.OpStatus}, &resp)
	if resp.Code != control.CodeRefused || !strings.Contains(resp.Error, "identify") {
		t.Fatalf("unidentifiable peer = %+v", resp)
	}

	// A peer whose pidfd stops matching is refused once its request is read.
	h.srv.cfg.Identify = func(control.Conn) (*Identity, error) {
		return &Identity{UID: 1000, PID: 1, pin: okPin{err: ErrPeerGone}}, nil
	}
	call(brokerapi.Request{Op: brokerapi.OpStatus}, &resp)
	if resp.OK || resp.Code != control.CodeRefused || !strings.Contains(resp.Error, "no longer matches") {
		t.Fatalf("a recycled pid = %+v", resp)
	}
}

func TestServeOverSocket(t *testing.T) {
	h := newHarness(t, nil)
	h.srv.cfg.Identify = func(control.Conn) (*Identity, error) {
		return &Identity{UID: 1000, PID: os.Getpid(), Start: "1", pin: okPin{}}, nil
	}
	call, stop := h.serve(t)

	var st brokerapi.Response
	call(brokerapi.Request{Op: brokerapi.OpStatus}, &st)
	if !st.OK || st.Status.Mode != "broker" || st.Status.UID != 1000 || st.Status.KeyID == "" || st.Status.Version != "test" {
		t.Fatalf("status = %+v", st)
	}

	// A raw client skipping presence is refused over the wire too.
	var raw brokerapi.Response
	call(map[string]any{"op": "secret.set", "path": "svc/key", "value": "AAAA"}, &raw)
	if raw.OK || raw.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("raw set = %+v", raw)
	}
	// Garbage broker frames are refused by Decode, not by a handler.
	call(map[string]any{"op": "secret.set", "bogus": 1}, &raw)
	if raw.OK || raw.Code != brokerapi.CodeBadRequest {
		t.Fatalf("malformed frame = %+v", raw)
	}
	// An operation neither protocol knows is refused by the control server.
	var unknown control.Response
	call(map[string]any{"op": "nonsense"}, &unknown)
	if unknown.Code != control.CodeBadRequest {
		t.Fatalf("unknown op = %+v", unknown)
	}

	// Full flow over the socket: begin, then set with the proof.
	var begin brokerapi.Response
	call(brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &setReq}, &begin)
	if !begin.OK {
		t.Fatalf("begin = %+v", begin)
	}
	withProof := setReq
	withProof.Proof = begin.Proof.ID
	call(withProof, &raw)
	if !raw.OK {
		t.Fatalf("set with proof = %+v", raw)
	}
	var list brokerapi.Response
	call(brokerapi.Request{Op: brokerapi.OpSecretList}, &list)
	if len(list.Entries) != 1 || list.Entries[0].Path != "svc/key" {
		t.Fatalf("list = %+v", list)
	}
	stop()
}

func TestNewRequiresPieces(t *testing.T) {
	keys := testKeys(t)
	for name, cfg := range map[string]Config{
		"no keys":  {Audit: &recorder{}, StateRoot: "x"},
		"no audit": {Keys: keys, StateRoot: "x"},
		"no state": {Keys: keys, Audit: &recorder{}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New must refuse", name)
		}
	}
}

func TestSecretOperations(t *testing.T) {
	h := newHarness(t, nil)
	setSecret(t, h, 1000, "a/b", "one")
	setSecret(t, h, 1000, "a/b", "two")

	if list := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretList}); len(list.Entries) != 1 || list.Entries[0].Version != 2 {
		t.Fatalf("list = %+v", list.Entries)
	}
	if st := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpStatus}).Status; st.Secrets != 1 || st.Policy != PolicyAbsent {
		t.Fatalf("status = %+v", st)
	}
	del := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: "a/b"})
	if resp := h.send(t, 1000, del); !resp.OK {
		t.Fatalf("delete = %+v", resp)
	}
	del = h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: "a/b"})
	if resp := h.send(t, 1000, del); resp.OK || resp.Code != brokerapi.CodeNotFound {
		t.Fatalf("second delete = %+v", resp)
	}
	bad := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: "../x"})
	if resp := h.send(t, 1000, bad); resp.OK || resp.Code != brokerapi.CodeBadRequest {
		t.Fatalf("delete of a bad path = %+v", resp)
	}
	badSet := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretSet, Path: "/abs", Value: []byte("x")})
	if resp := h.send(t, 1000, badSet); resp.OK || resp.Code != brokerapi.CodeBadRequest {
		t.Fatalf("set of a bad path = %+v", resp)
	}
	if h.rec.count(audit.ActionSet) != 2 || h.rec.count(audit.ActionDelete) != 1 {
		t.Fatalf("audit: %d sets, %d deletes", h.rec.count(audit.ActionSet), h.rec.count(audit.ActionDelete))
	}
	for _, e := range h.rec.events {
		for _, v := range e.Extra {
			if s, ok := v.(string); ok && (s == "one" || s == "two") {
				t.Fatalf("audit event %s carries a value", e.Action)
			}
		}
	}

	// A refused audit write refuses the operation's success.
	h.rec.fail = errors.New("disk full")
	req := h.proven2(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretSet, Path: "c", Value: []byte("x")})
	if resp := h.send(t, 1000, req); resp.OK {
		t.Fatalf("a set that cannot be audited reported success: %+v", resp)
	}
}

// proven2 issues a proof directly, for tests that make the audit log fail.
func (h *harness) proven2(t *testing.T, uid uint32, req brokerapi.Request) brokerapi.Request {
	t.Helper()
	req.Proof = h.srv.proofs.Issue(uid, req.Digest(), "fake").ID
	return req
}

func TestMigrationVerifiesKeyedHashes(t *testing.T) {
	h := newHarness(t, nil)
	nonce := bytes.Repeat([]byte{3}, 16)
	items := []brokerapi.Item{{Path: "github/token", Value: []byte("first-value")}, {Path: "aws/key", Value: []byte("second-value")}, {Path: "empty", Value: nil}}
	req := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpMigrateImport, Items: items, Nonce: nonce, OldAuditHead: "ab12"})
	resp := h.send(t, 1000, req)
	if !resp.OK || len(resp.MACs) != len(items) {
		t.Fatalf("migrate.import = %+v", resp)
	}
	for _, it := range items {
		if resp.MACs[it.Path] != KeyedHash(nonce, it.Path, it.Value) {
			t.Fatalf("keyed hash of %s does not match the client's", it.Path)
		}
	}
	if ev, ok := h.rec.last(audit.ActionBrokerAdopt); !ok || ev.Extra["count"] != 3 || ev.Extra["old_audit_head"] != "ab12" {
		t.Fatalf("adopt event = %+v", ev)
	}
	// The wrong nonce gives a different hash, so a stale answer cannot pass.
	if KeyedHash([]byte("other-nonce-0000"), "aws/key", []byte("second-value")) == resp.MACs["aws/key"] {
		t.Fatal("the keyed hash ignores the nonce")
	}

	out := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpMigrateExport})
	exp := h.send(t, 1000, out)
	if !exp.OK || len(exp.Items) != 3 {
		t.Fatalf("migrate.export = %+v", exp)
	}
	got := map[string]string{}
	for _, it := range exp.Items {
		got[it.Path] = string(it.Value)
	}
	if got["github/token"] != "first-value" || got["aws/key"] != "second-value" {
		t.Fatalf("exported %v", got)
	}
	if h.rec.count(audit.ActionBrokerExport) != 1 {
		t.Fatal("export is not audited")
	}
	// The other user exports nothing.
	otherOut := h.proven(t, 1001, brokerapi.Request{Op: brokerapi.OpMigrateExport})
	if resp := h.send(t, 1001, otherOut); len(resp.Items) != 0 {
		t.Fatalf("user B exported %d items", len(resp.Items))
	}
}

func TestRotateKeysRewrapsEveryPartition(t *testing.T) {
	h := newHarness(t, nil)
	setSecret(t, h, 1000, "a", "alpha")
	setSecret(t, h, 1001, "b", "beta")
	before := h.srv.cfg.Keys.KeyID()
	pub, _ := h.srv.cfg.Keys.Public("policy-signing")

	req := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpRotateKeys})
	resp := h.send(t, 1000, req)
	if !resp.OK || resp.Status.KeyID == before || resp.Status.RotationPending {
		t.Fatalf("rotate = %+v", resp)
	}
	for uid, c := range map[uint32][2]string{1000: {"a", "alpha"}, 1001: {"b", "beta"}} {
		p, _ := h.srv.partition(context.Background(), uid)
		if got, _, err := p.store.Get(context.Background(), c[0]); err != nil || string(got) != c[1] {
			t.Fatalf("user %d after rotation: %q, %v", uid, got, err)
		}
	}
	if after, _ := h.srv.cfg.Keys.Public("policy-signing"); !bytes.Equal(pub, after) {
		t.Fatal("rotation changed a signing key")
	}
	if ev, ok := h.rec.last(audit.ActionKEKRotate); !ok || !strings.HasPrefix(ev.Extra["new_kek_type"].(string), "bmk:") {
		t.Fatalf("rotation event = %+v", ev)
	}
}

func TestResumeRotationAfterInterruption(t *testing.T) {
	h := newHarness(t, nil)
	setSecret(t, h, 1000, "a", "alpha")
	// Stage a rotation whose data rewrap fails.
	_ = h.srv.cfg.Keys.Rotate(func(_, _ keys.KEKFunc, _ string) error { return errors.New("crash") })
	if !h.srv.cfg.Keys.Pending() {
		t.Fatal("no rotation staged")
	}
	if err := h.srv.ResumeRotation(); err != nil {
		t.Fatal(err)
	}
	if h.srv.cfg.Keys.Pending() {
		t.Fatal("ResumeRotation left the rotation staged")
	}
	p, _ := h.srv.partition(context.Background(), 1000)
	if got, _, err := p.store.Get(context.Background(), "a"); err != nil || string(got) != "alpha" {
		t.Fatalf("after resume: %q, %v", got, err)
	}
}

func TestAuditHeadAndUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpAuditHead})
	if !resp.OK || resp.Head.Hash != "ab12" || resp.Head.Events != 7 {
		t.Fatalf("head = %+v", resp)
	}
	h2 := newHarness(t, func(c *Config) { c.AuditHead = nil })
	if resp := h2.send(t, 1000, brokerapi.Request{Op: brokerapi.OpAuditHead}); resp.OK || resp.Code != brokerapi.CodeUnavailable {
		t.Fatalf("head without a logger = %+v", resp)
	}
}

func TestExtensionIgnoresControlOps(t *testing.T) {
	h := newHarness(t, nil)
	p, _ := h.srv.partition(context.Background(), 1000)
	if (&admin{s: h.srv, p: p}).Handle(context.Background(), nil, control.Peer{}, host, []byte(`{"op":"exec"}`)) {
		t.Fatal("the extension must leave control operations to the control server")
	}
}

func TestStoreOfPartitionIsBrokerStore(t *testing.T) {
	h := newHarness(t, nil)
	p, _ := h.srv.partition(context.Background(), 1000)
	var _ interface {
		Get(context.Context, string) ([]byte, backend.Meta, error)
	} = p.store
	if _, _, err := p.store.Get(context.Background(), "missing"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatal(err)
	}
}
