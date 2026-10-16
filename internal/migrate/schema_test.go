package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/schemas"
)

func compile(t *testing.T, name string, body []byte) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	if err := c.AddResource(name, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func yamlToGeneric(t *testing.T, doc string) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	var g any
	_ = json.Unmarshal(b, &g)
	return g
}

func TestMigrateSchemasMatchParsers(t *testing.T) {
	mapSchema := compile(t, "map.json", schemas.MigrateMap)
	good := `version: 1
collections: {apps: app-secrets}
sources:
  - {type: env-file, namespace: apps, glob: "~/x/.env*"}
  - {type: secret-service, namespace: pay, service: pay}
  - {type: keychain, namespace: mac, service: s, accounts: [a]}
  - {type: gh, namespace: github, hosts: [github.com]}
  - {type: password-manager, namespace: pm, manager: op, items: [i]}
`
	if err := mapSchema.Validate(yamlToGeneric(t, good)); err != nil {
		t.Fatalf("schema rejects a valid map: %v", err)
	}
	if _, err := ParseMap([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown key": "version: 1\nsources: [{type: gh, namespace: a, nope: 1}]",
		"env glob":    "version: 1\nsources: [{type: env-file, namespace: a}]",
		"namespace":   "version: 1\nsources: [{type: gh, namespace: 'Bad'}]",
		"manager":     "version: 1\nsources: [{type: password-manager, namespace: a, manager: x, items: [i]}]",
		"empty":       "version: 1\nsources: []",
		"version":     "version: 2\nsources: [{type: gh, namespace: a}]",
	} {
		if mapSchema.Validate(yamlToGeneric(t, doc)) == nil {
			t.Errorf("%s: schema accepts what ParseMap rejects", name)
		}
		if _, err := ParseMap([]byte(doc)); err == nil {
			t.Errorf("%s: ParseMap accepts it", name)
		}
	}

	env, _ := testEnv(t)
	plan, err := Inventory(context.Background(), testMap(t), env)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(plan)
	var g any
	_ = json.Unmarshal(b, &g)
	if err := compile(t, "plan.json", schemas.MigratePlan).Validate(g); err != nil {
		t.Fatalf("schema rejects an inventory: %v", err)
	}
}
