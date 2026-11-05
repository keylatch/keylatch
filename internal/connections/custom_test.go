package connections

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

func customOpts(caller CallerKind, hosts ...string) CustomOptions {
	return CustomOptions{
		Fields: map[string][]byte{"api_key": []byte("op://Dev/Billing API/credential")},
		Binding: registry.CustomBinding{
			Hosts: hosts,
			Slots: []registry.Slot{{Field: "api_key", In: registry.SlotHeader, Name: "Authorization", Scheme: "Bearer", Hosts: hosts}},
			Shape: registry.PlaceholderShape{MinLength: registry.DefaultCustomMinLength},
			Env:   map[string]string{"api_key": "BILLING_API_KEY"},
		},
		Caller: caller,
	}
}

func TestSaveCustom_AgentCannotCreate(t *testing.T) {
	st := newMockStore()
	change, err := SaveCustom(context.Background(), "billing-internal", customOpts(CallerAgent, "api.billing.example:443"), st)
	if !errors.Is(err, ErrBindingHumanOnly) || change.Kind != ChangeCreated {
		t.Fatalf("change=%+v err=%v", change, err)
	}
	if len(st.data) != 0 {
		t.Fatalf("refused create wrote %d entries", len(st.data))
	}
}

func TestSaveCustom_HumanCreatesAndBindingResolves(t *testing.T) {
	ctx, st := context.Background(), newMockStore()
	if _, err := SaveCustom(ctx, "billing-internal", customOpts(CallerHuman, "api.billing.example:443"), st); err != nil {
		t.Fatal(err)
	}
	b, err := CustomBindingFor(ctx, st, "", "billing-internal")
	if err != nil {
		t.Fatal(err)
	}
	if !b.AllowsHost("api.billing.example:443") || len(b.SlotsFor("api_key", "api.billing.example:443")) != 1 || b.Env["api_key"] != "BILLING_API_KEY" {
		t.Fatalf("binding = %+v", b)
	}
	fields, ok, err := CustomFields(ctx, st, "", "billing-internal")
	if err != nil || !ok || len(fields) != 1 || fields[0] != "api_key" {
		t.Fatalf("fields=%v ok=%v err=%v", fields, ok, err)
	}
}

func TestSaveCustom_WidenHumanOnlyNarrowAnyCaller(t *testing.T) {
	ctx, st := context.Background(), newMockStore()
	two := customOpts(CallerHuman, "a.example.com:443", "b.example.com:443")
	if _, err := SaveCustom(ctx, "svc", two, st); err != nil {
		t.Fatal(err)
	}

	wide := customOpts(CallerAgent, "a.example.com:443", "b.example.com:443", "evil.example.org:443")
	wide.Fields = nil
	change, err := SaveCustom(ctx, "svc", wide, st)
	if !errors.Is(err, ErrBindingHumanOnly) || change.Kind != ChangeWidened {
		t.Fatalf("change=%+v err=%v", change, err)
	}
	if len(change.HostsBefore) != 2 || len(change.HostsAfter) != 3 {
		t.Fatalf("host sets = %v -> %v", change.HostsBefore, change.HostsAfter)
	}
	b, _ := CustomBindingFor(ctx, st, "", "svc")
	if b.AllowsHost("evil.example.org:443") {
		t.Fatal("refused widening was applied")
	}

	narrow := customOpts(CallerAgent, "a.example.com:443")
	narrow.Fields = nil
	change, err = SaveCustom(ctx, "svc", narrow, st)
	if err != nil || change.Kind != ChangeNarrowed {
		t.Fatalf("change=%+v err=%v", change, err)
	}
	b, _ = CustomBindingFor(ctx, st, "", "svc")
	if b.AllowsHost("b.example.com:443") {
		t.Fatal("narrowing not applied")
	}
}

func TestSaveCustom_RejectsInvalidBinding(t *testing.T) {
	for _, host := range []string{"*", "*.com", "*.co.uk"} {
		if _, err := SaveCustom(context.Background(), "svc", customOpts(CallerHuman, host), newMockStore()); err == nil {
			t.Errorf("host %q accepted", host)
		}
	}
	if _, err := SaveCustom(context.Background(), "Bad Name", customOpts(CallerHuman, "a.example.com:443"), newMockStore()); err == nil {
		t.Error("invalid name accepted")
	}
}

func TestCustomBindingFor_NoBinding(t *testing.T) {
	_, err := CustomBindingFor(context.Background(), newMockStore(), "", "missing")
	if !errors.Is(err, registry.ErrNoBinding) {
		t.Fatalf("err = %v", err)
	}
}

func TestCustomTemplate_ExposesBindingAndFields(t *testing.T) {
	ctx, st := context.Background(), newMockStore()
	if _, err := SaveCustom(ctx, "billing-internal", customOpts(CallerHuman, "api.billing.example:443"), st); err != nil {
		t.Fatal(err)
	}
	tmpl, err := CustomTemplate(ctx, st, "", "billing-internal")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := tmpl.Binding()
	if !ok || !b.AllowsHost("api.billing.example:443") || len(tmpl.InjectionRules) != 1 || tmpl.InjectionRules[0].EnvVar != "BILLING_API_KEY" || tmpl.InjectionRules[0].Source != "api_key" {
		t.Fatalf("template = %+v", tmpl)
	}
	if got := CustomSecretPath("", "billing-internal", "api_key"); got != "default/custom/billing-internal/api_key" {
		t.Fatalf("path = %q", got)
	}
	if _, err := CustomTemplate(ctx, st, "", "missing"); !errors.Is(err, registry.ErrNoBinding) {
		t.Fatalf("err = %v", err)
	}
	if !ValidCustomName("billing-internal") || ValidCustomName("Bad Name") {
		t.Fatal("ValidCustomName")
	}
}
