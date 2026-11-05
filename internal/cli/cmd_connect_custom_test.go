package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
)

type mapStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMapStore() *mapStore { return &mapStore{data: map[string][]byte{}} }

func (m *mapStore) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[p]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return v, backend.Meta{Path: p}, nil
}

func (m *mapStore) Set(_ context.Context, p string, v []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[p] = append([]byte(nil), v...)
	return nil
}

func (m *mapStore) List(context.Context, string) ([]backend.Entry, error) { return nil, nil }

func (m *mapStore) Delete(_ context.Context, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, p)
	return nil
}

type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) error {
	r.events = append(r.events, e)
	return nil
}

func customInputFor(hosts ...string) customConnectInput {
	return customConnectInput{
		Hosts:     hosts,
		Slots:     []string{"header:Authorization:Bearer"},
		Envs:      []string{"BILLING_API_KEY"},
		MinLength: 32,
		Fields:    map[string][]byte{"api_key": []byte("op://Dev/Billing API/credential")},
	}
}

func TestConnectCustom_AgentRefusedAndAudited(t *testing.T) {
	st, em := newMapStore(), &recordingEmitter{}
	err := connectCustom(context.Background(), &bytes.Buffer{}, st, "billing-internal", customInputFor("api.billing.example:443"), connections.CallerAgent, em)
	var ce *CLIError
	if !errors.As(err, &ce) || ce.Code != exitcode.SecurityBlock {
		t.Fatalf("err = %v", err)
	}
	if len(st.data) != 0 {
		t.Fatal("agent create wrote state")
	}
	if len(em.events) != 1 || em.events[0].Action != audit.ActionBindingRefused || em.events[0].Outcome != audit.OutcomeDenied {
		t.Fatalf("events = %+v", em.events)
	}
	x := em.events[0].Extra
	if x["caller_kind"] != "agent" || x["attempted"] != connections.ChangeCreated {
		t.Fatalf("extra = %v", x)
	}
}

func TestConnectCustom_HumanCreateThenAgentWidenRefusedNarrowAllowed(t *testing.T) {
	ctx, st, em := context.Background(), newMapStore(), &recordingEmitter{}
	out := &bytes.Buffer{}
	if err := connectCustom(ctx, out, st, "billing-internal", customInputFor("a.example.com:443", "b.example.com:443"), connections.CallerHuman, em); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "created") {
		t.Fatalf("out = %q", out.String())
	}

	wide := customInputFor("a.example.com:443", "b.example.com:443", "evil.example.org:443")
	wide.Fields = nil
	if err := connectCustom(ctx, out, st, "billing-internal", wide, connections.CallerAgent, em); err == nil {
		t.Fatal("agent widening accepted")
	}
	last := em.events[len(em.events)-1]
	if last.Action != audit.ActionBindingRefused || last.Extra["attempted"] != connections.ChangeWidened {
		t.Fatalf("last = %+v", last)
	}
	if len(last.Extra["hosts_before"].([]string)) != 2 || len(last.Extra["hosts_after"].([]string)) != 3 {
		t.Fatalf("host sets = %v", last.Extra)
	}

	narrow := customInputFor("a.example.com:443")
	narrow.Fields = nil
	if err := connectCustom(ctx, out, st, "billing-internal", narrow, connections.CallerAgent, em); err != nil {
		t.Fatal(err)
	}
	last = em.events[len(em.events)-1]
	if last.Action != audit.ActionBindingNarrowed || last.Outcome != audit.OutcomeOK {
		t.Fatalf("last = %+v", last)
	}
	b, err := connections.CustomBindingFor(ctx, st, "", "billing-internal")
	if err != nil || b.AllowsHost("b.example.com:443") || !b.AllowsHost("a.example.com:443") {
		t.Fatalf("binding = %+v err = %v", b, err)
	}
}

func TestConnectCustom_RejectsUnsafeHosts(t *testing.T) {
	for _, h := range []string{"*", "*.com", "*.co.uk"} {
		err := connectCustom(context.Background(), &bytes.Buffer{}, newMapStore(), "svc", customInputFor(h), connections.CallerHuman, nil)
		if err == nil {
			t.Errorf("host %q accepted", h)
		}
	}
}

func TestConnectCustom_MultiFieldNeedsFieldNames(t *testing.T) {
	in := customInputFor("a.example.com:443")
	in.Fields["other"] = []byte("v")
	if err := connectCustom(context.Background(), &bytes.Buffer{}, newMapStore(), "svc", in, connections.CallerHuman, nil); err == nil {
		t.Fatal("ambiguous slot field accepted")
	}
	in.Slots = []string{"api_key=header:Authorization:Bearer"}
	in.Envs = []string{"api_key=BILLING_API_KEY"}
	if err := connectCustom(context.Background(), &bytes.Buffer{}, newMapStore(), "svc", in, connections.CallerHuman, nil); err != nil {
		t.Fatal(err)
	}
}
