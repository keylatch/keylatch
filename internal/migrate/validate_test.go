package migrate

import (
	"context"
	"strings"
	"testing"
)

func TestInventoryPlanValidatesAgainstItsMap(t *testing.T) {
	e, _ := testEnv(t)
	m := testMap(t)
	plan, err := Inventory(context.Background(), m, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlan(m, plan, e); err != nil {
		t.Fatalf("a plan the scan made was refused: %v", err)
	}
}

func TestForgedPlanItemsAreRefused(t *testing.T) {
	e, home := testEnv(t)
	m := testMap(t)
	plan, err := Inventory(context.Background(), m, e)
	if err != nil {
		t.Fatal(err)
	}
	var envItem PlanItem
	for _, it := range plan.Items {
		if it.Source == SourceEnvFile {
			envItem = it
		}
	}
	forge := map[string]func(PlanItem) PlanItem{
		"a file outside the globs": func(it PlanItem) PlanItem { it.Ref = "env:/etc/shadow#root"; return it },
		"a file with dot segments": func(it PlanItem) PlanItem {
			it.Ref = "env:" + home + "/proj/../../etc/passwd#x"
			return it
		},
		"a relative file":      func(it PlanItem) PlanItem { it.Ref = "env:proj/.env#API_KEY"; return it },
		"no key":               func(it PlanItem) PlanItem { it.Ref = "env:" + home + "/proj/.env#"; return it },
		"another path":         func(it PlanItem) PlanItem { it.Path = "apps/elsewhere"; return it },
		"another collection":   func(it PlanItem) PlanItem { it.Collection = "other"; return it },
		"another namespace":    func(it PlanItem) PlanItem { it.Namespace = "pay"; return it },
		"an unmapped source":   func(it PlanItem) PlanItem { it.Source = SourceKeychain; return it },
		"a lookup of a secret": func(it PlanItem) PlanItem { it.Source, it.Ref = SourceSecretService, "ss:other:x"; return it },
	}
	for name, mutate := range forge {
		p := Plan{Version: 1, Items: []PlanItem{mutate(envItem)}}
		if err := ValidatePlan(m, p, e); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	cases := []PlanItem{
		{Name: "x", Source: SourceSecretService, Ref: "ss:other:x", Namespace: "pay"},
		{Name: "x", Source: SourceKeychain, Ref: "kc:svc:two", Namespace: "mac"},
		{Name: "x", Source: SourceKeychain, Ref: "kc:other:one", Namespace: "mac"},
		{Name: "x", Source: SourceGitHubCLI, Ref: "gh:--help", Namespace: "github"},
		{Name: "x", Source: SourcePasswordManager, Ref: "pm:op:My Item", Namespace: "pm"},
		{Name: "x", Source: SourcePasswordManager, Ref: "pm:bw:Other", Namespace: "pm"},
		{Name: "x", Source: "bogus", Ref: "bogus:x", Namespace: "pay"},
	}
	for _, it := range cases {
		it.Collection, it.Path = itemPath(m, it.Namespace, it.Name)
		if err := ValidatePlan(m, Plan{Version: 1, Items: []PlanItem{it}}, e); err == nil {
			t.Errorf("%s was accepted", it.Ref)
		}
	}
}

func TestGitHubHostsLimitTheReferences(t *testing.T) {
	e, _ := testEnv(t)
	m, err := ParseMap([]byte("version: 1\nsources:\n  - {type: gh, namespace: github, hosts: [github.com]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	item := func(host string) Plan {
		it := PlanItem{Name: "gh-" + host, Source: SourceGitHubCLI, Ref: "gh:" + host, Namespace: "github"}
		it.Collection, it.Path = itemPath(m, "github", it.Name)
		return Plan{Version: 1, Items: []PlanItem{it}}
	}
	if err := ValidatePlan(m, item("github.com"), e); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlan(m, item("evil.test"), e); err == nil || !strings.Contains(err.Error(), "not within") {
		t.Fatalf("a host outside the map: %v", err)
	}
}

func TestCommandBackedItems(t *testing.T) {
	if (PlanItem{Ref: "env:/a#B"}).CommandBacked() {
		t.Error("an env file runs no program")
	}
	for _, ref := range []string{"ss:a:b", "kc:a:b", "gh:h", "pm:bw:i"} {
		if !(PlanItem{Ref: ref}).CommandBacked() {
			t.Errorf("%s runs a program", ref)
		}
	}
}
