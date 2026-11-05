//go:build unix

package brokerd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// userDaemon is the broker as one user's CLI sees it, backed by the harness.
type userDaemon struct {
	t   *testing.T
	h   *harness
	uid uint32
	// tamper rewrites the daemon's reply, to stand in for a corrupted transfer.
	tamper func(*brokerapi.Response)
}

func (d *userDaemon) Call(req brokerapi.Request) (brokerapi.Response, error) {
	resp := d.h.send(d.t, d.uid, req)
	if d.tamper != nil {
		d.tamper(&resp)
	}
	return resp, nil
}

type fakeSource struct {
	items    []brokerapi.Item
	policy   map[string][]byte
	head     string
	tokens   int
	shredded []string
	order    []string
	readErr  error
}

func (s *fakeSource) Secrets(context.Context) ([]brokerapi.Item, error) {
	s.order = append(s.order, "secrets")
	return append([]brokerapi.Item(nil), s.items...), s.readErr
}
func (s *fakeSource) PolicyFiles() (map[string][]byte, error) { return s.policy, nil }
func (s *fakeSource) AuditHead() (string, error)              { return s.head, nil }
func (s *fakeSource) RevokeTokens(context.Context) (int, error) {
	s.order = append(s.order, "revoke")
	return s.tokens, nil
}
func (s *fakeSource) Shred() ([]string, error) {
	s.order = append(s.order, "shred")
	return s.shredded, nil
}

func sampleSource() *fakeSource {
	return &fakeSource{
		items: []brokerapi.Item{
			{Path: "github/token", Value: []byte("first-value")},
			{Path: "openai/key", Value: []byte("second-value")},
			{Path: "stripe/key", Value: []byte("third-value")},
		},
		policy:   map[string][]byte{"policy.json": []byte(`{"default_deny":true}`)},
		head:     "feedbeef",
		tokens:   2,
		shredded: []string{"keyring/identity", "keyring.json", "signing.key", "audit-salt"},
	}
}

func TestBrokerInstallAndAdopt(t *testing.T) {
	// Install against a fake root with fake systemctl and systemd-creds.
	in, runner, root := newInstaller(t)
	if _, err := in.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 || root == "" {
		t.Fatalf("install commands = %v", runner.calls)
	}

	// Then adopt N secrets through a presence-gated daemon.
	h := newHarness(t, nil)
	src := sampleSource()
	res, err := Adopt(context.Background(), src, &userDaemon{t: t, h: h, uid: 1000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secrets != 3 || res.Verified != 3 || res.PolicyFiles != 1 || res.TokensRevoked != 2 || len(res.Shredded) != 4 || res.OldAuditHead != "feedbeef" {
		t.Fatalf("result = %+v", res)
	}
	if got := strings.Join(src.order, ","); got != "secrets,revoke,shred" {
		t.Fatalf("order = %s: tokens must be revoked and keys shredded only after the move", got)
	}
	// The secrets are in user 1000's partition and the policy is signed.
	p, _ := h.srv.partition(context.Background(), 1000)
	if got, _, err := p.store.Get(context.Background(), "openai/key"); err != nil || string(got) != "second-value" {
		t.Fatalf("adopted secret = %q, %v", got, err)
	}
	if st := p.policy.Verify(); st.State != PolicySigned {
		t.Fatalf("adopted policy is %s", st.State)
	}
	// Doctor's rotate-recommended list names every upstream key.
	if len(res.RotateUpstream) != 3 {
		t.Fatalf("RotateUpstream = %v", res.RotateUpstream)
	}
	// Both the move and the policy needed their own presence.
	if len(h.pres.actions) != 2 || h.pres.actions[0] != "broker.adopt" || h.pres.actions[1] != "policy.change" {
		t.Fatalf("presence prompts = %v", h.pres.actions)
	}
}

func TestAdoptVerifiesKeyedHashes(t *testing.T) {
	for name, tamper := range map[string]func(*brokerapi.Response){
		"a wrong hash":   func(r *brokerapi.Response) { r.MACs["openai/key"] = strings.Repeat("0", 64) },
		"a missing hash": func(r *brokerapi.Response) { delete(r.MACs, "github/token") },
		"an extra hash":  func(r *brokerapi.Response) { r.MACs["extra"] = "x" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			src := sampleSource()
			d := &userDaemon{t: t, h: h, uid: 1000}
			d.tamper = func(r *brokerapi.Response) {
				if r.MACs != nil {
					tamper(r)
				}
			}
			_, err := Adopt(context.Background(), src, d, nil)
			if !errors.Is(err, ErrVerify) {
				t.Fatalf("Adopt = %v, want ErrVerify", err)
			}
			if len(src.order) != 1 {
				t.Fatalf("after a failed check the in-user install was touched: %v", src.order)
			}
		})
	}
}

func TestAdoptStopsWhenPresenceIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.pres.err = errors.New("polkit refused (exit 126)")
	src := sampleSource()
	if _, err := Adopt(context.Background(), src, &userDaemon{t: t, h: h, uid: 1000}, nil); err == nil {
		t.Fatal("adopt must fail when the human does not approve")
	}
	if len(src.order) != 1 {
		t.Fatalf("a refused adopt touched the in-user install: %v", src.order)
	}
	if p, _ := h.srv.partition(context.Background(), 1000); func() int { e, _ := p.store.List(context.Background(), ""); return len(e) }() != 0 {
		t.Fatal("a refused adopt stored secrets")
	}
}

func TestAdoptSourceErrors(t *testing.T) {
	h := newHarness(t, nil)
	d := &userDaemon{t: t, h: h, uid: 1000}
	src := sampleSource()
	src.readErr = errors.New("kek locked")
	if _, err := Adopt(context.Background(), src, d, nil); err == nil || !strings.Contains(err.Error(), "in-user store") {
		t.Fatalf("unreadable store = %v", err)
	}
	// An empty install adopts nothing but still succeeds.
	empty := &fakeSource{}
	res, err := Adopt(context.Background(), empty, d, nil)
	if err != nil || res.Secrets != 0 {
		t.Fatalf("empty adopt = %+v, %v", res, err)
	}
}

type memSink struct {
	prepared bool
	items    map[string]string
	putErr   error
	prepErr  error
}

func (s *memSink) Prepare(context.Context) error { s.prepared = true; return s.prepErr }
func (s *memSink) Put(_ context.Context, p string, v []byte) error {
	if s.putErr != nil {
		return s.putErr
	}
	if s.items == nil {
		s.items = map[string]string{}
	}
	s.items[p] = string(v)
	return nil
}

func TestExportToUserRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	d := &userDaemon{t: t, h: h, uid: 1000}
	src := sampleSource()
	if _, err := Adopt(context.Background(), src, d, nil); err != nil {
		t.Fatal(err)
	}

	sink := &memSink{}
	n, err := ExportToUser(context.Background(), d, sink)
	if err != nil || n != 3 || !sink.prepared {
		t.Fatalf("ExportToUser = %d, %v (prepared %v)", n, err, sink.prepared)
	}
	for _, it := range sampleSource().items {
		if sink.items[it.Path] != string(it.Value) {
			t.Fatalf("%s restored as %q", it.Path, sink.items[it.Path])
		}
	}
	// The export needed presence of its own.
	if last := h.pres.actions[len(h.pres.actions)-1]; last != "broker.export" {
		t.Fatalf("last prompt = %q", last)
	}

	// Failure modes.
	h.pres.err = errors.New("denied")
	if _, err := ExportToUser(context.Background(), d, sink); err == nil {
		t.Fatal("export without presence must fail")
	}
	h.pres.err = nil
	if _, err := ExportToUser(context.Background(), d, &memSink{prepErr: errors.New("no keyring")}); err == nil {
		t.Fatal("a sink that cannot prepare must fail")
	}
	if n, err := ExportToUser(context.Background(), d, &memSink{putErr: errors.New("disk full")}); err == nil || n != 0 {
		t.Fatalf("a sink that cannot write = %d, %v", n, err)
	}
}

func TestProveReportsRefusals(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Presence = nil })
	_, err := Prove(&userDaemon{t: t, h: h, uid: 1000}, brokerapi.Request{Op: brokerapi.OpRotateKeys})
	if err == nil || !strings.Contains(err.Error(), "presence") {
		t.Fatalf("Prove without a presence method = %v", err)
	}
}
