package sync

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/schemas"
)

type fakeRepo struct {
	ignored, tracked map[string]bool
	err              error
}

func (r fakeRepo) Ignored(p string) (bool, error) { return r.ignored[p], r.err }
func (r fakeRepo) Tracked(p string) (bool, error) { return r.tracked[p], r.err }

var ignoredEnv = fakeRepo{ignored: map[string]bool{".env.local": true}}

const goodManifest = `version: 1
targets:
  web:   {type: vercel, project: prj_1, team: team_1, credential: vercel-deploy}
  ci:    {type: github-actions, repo: owner/app, environments: [production], credential: github-app-ci}
  local: {type: env-file, path: .env.local}
vars:
  - name: DATABASE_URL
    from: {connection: app-db, field: url}
    to: {web: [production, preview], ci: [repository, production], local: [file]}
  - name: FLAG
    from: {connection: flags}
    sensitive: false
    to: {web: [development]}
`

func TestSyncManifestValidation(t *testing.T) {
	m, err := Parse([]byte(goodManifest), ignoredEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Vars[0].IsSensitive() || m.Vars[1].IsSensitive() {
		t.Fatal("sensitive must default to true")
	}
	if got := strings.Join(m.TargetNames(), ","); got != "ci,local,web" {
		t.Fatalf("targets = %s", got)
	}

	cases := []struct{ name, edit, with, want string }{
		{"unknown top key", "version: 1\n", "version: 1\nextra: 1\n", "extra"},
		{"unknown target key", "project: prj_1,", "project: prj_1, nope: 1,", "targets.web.nope"},
		{"unknown var key", "  - name: FLAG\n", "  - name: FLAG\n    colour: red\n", "vars[1].colour"},
		{"unknown from key", "from: {connection: flags}", "from: {connection: flags, x: 1}", "vars[1].from.x"},
		{"version", "version: 1\n", "version: 2\n", "version"},
		{"vercel needs project or link", "project: prj_1, ", "", "targets.web"},
		{"vercel both project and link", "project: prj_1,", "project: prj_1, link: .vercel/project.json,", "exactly one"},
		{"vercel credential", ", credential: vercel-deploy}", "}", "targets.web.credential"},
		{"vercel repo", "project: prj_1,", "project: prj_1, repo: a/b,", "targets.web.repo"},
		{"github repo shape", "repo: owner/app", "repo: owner", "targets.ci.repo"},
		{"github env named repository", "environments: [production]", "environments: [repository]", "targets.ci.environments[0]"},
		{"unknown target type", "type: env-file", "type: ftp", "targets.local.type"},
		{"unknown target in to", "to: {web: [development]}", "to: {nowhere: [x]}", "unknown target"},
		{"unknown vercel env", "web: [production, preview]", "web: [staging]", "vars[0].to.web[0]"},
		{"unknown github env", "ci: [repository, production]", "ci: [repository, qa]", "vars[0].to.ci[1]"},
		{"sensitive in development", "web: [production, preview]", "web: [production, development]", "development"},
		{"empty env list", "web: [production, preview]", "web: []", "vars[0].to.web"},
		{"lower case github secret", "name: DATABASE_URL", "name: database_url", "upper case"},
		{"GITHUB_ prefix", "name: DATABASE_URL", "name: GITHUB_TOKEN", "GITHUB_"},
		{"bad name", "name: FLAG", "name: 1FLAG", "vars[1].name"},
		{"missing connection", "from: {connection: flags}", "from: {field: x}", "vars[1].from.connection"},
		{"duplicate name", "  - name: FLAG\n    from: {connection: flags}\n    sensitive: false\n    to: {web: [development]}\n",
			"  - name: FLAG\n    from: {connection: flags}\n    sensitive: false\n    to: {web: [development]}\n  - name: FLAG\n    from: {connection: other}\n    sensitive: false\n    to: {web: [development]}\n", "already declared"},
		{"verify not https", "name: FLAG\n", "name: FLAG\n    verify: {url: http://x.test}\n", "vars[1].verify.url"},
		{"env-file credential", "path: .env.local", "path: .env.local, credential: x", "targets.local.credential"},
	}
	for _, tc := range cases {
		doc := strings.Replace(goodManifest, tc.edit, tc.with, 1)
		if doc == goodManifest {
			t.Fatalf("%s: the edit did not apply", tc.name)
		}
		_, err := Parse([]byte(doc), ignoredEnv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	for name, doc := range map[string]string{
		"not yaml":      "version: [",
		"not a map":     "- a\n- b\n",
		"no targets":    "version: 1\ntargets: {}\nvars: []\n",
		"no vars":       "version: 1\ntargets: {a: {type: env-file, path: .env.local}}\nvars: []\n",
		"targets list":  "version: 1\ntargets: []\nvars: []\n",
		"vars map":      "version: 1\ntargets: {a: {type: env-file, path: .env.local}}\nvars: {}\n",
		"no to":         "version: 1\ntargets: {a: {type: env-file, path: .env.local}}\nvars: [{name: A, from: {connection: c}}]\n",
		"target scalar": "version: 1\ntargets: {a: 1}\nvars: []\n",
		"var scalar":    "version: 1\ntargets: {a: {type: env-file, path: .env.local}}\nvars: [1]\n",
	} {
		if _, err := Parse([]byte(doc), ignoredEnv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSyncEnvFileMustBeIgnored(t *testing.T) {
	doc := func(path string) []byte {
		return []byte("version: 1\ntargets:\n  local: {type: env-file, path: " + path + "}\nvars:\n  - {name: A, from: {connection: c}, to: {local: [file]}}\n")
	}
	for path, want := range map[string]string{
		"/etc/app.env":       "absolute",
		"../outside.env":     "inside the repository",
		".":                  "inside the repository",
		".env.committed":     "not git-ignored",
		"config/tracked.env": "tracked",
	} {
		repo := fakeRepo{ignored: map[string]bool{"config/tracked.env": true}, tracked: map[string]bool{"config/tracked.env": true}}
		_, err := Parse(doc(path), repo)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", path, err, want)
		}
	}
	if _, err := Parse(doc(".env.local"), ignoredEnv); err != nil {
		t.Fatalf("an ignored file was refused: %v", err)
	}
	if _, err := Parse(doc(".env.local"), nil); err != nil {
		t.Fatalf("without a repository checker the git rules are skipped: %v", err)
	}
	if _, err := Parse(doc(".env.local"), fakeRepo{err: errors.New("git failed")}); err == nil {
		t.Fatal("a git failure must refuse the manifest")
	}
}

func compileSyncSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	if err := c.AddResource("sync.json", bytes.NewReader(schemas.Sync)); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("sync.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func generic(t *testing.T, doc string) any {
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

func TestSyncSchemaMatchesParser(t *testing.T) {
	schema := compileSyncSchema(t)
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "keylatch.sync.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{"good": goodManifest, "example": string(example)} {
		if err := schema.Validate(generic(t, doc)); err != nil {
			t.Errorf("%s: the schema rejects a manifest the parser accepts: %v", name, err)
		}
		if _, err := Parse([]byte(doc), nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string][2]string{
		"unknown key":      {"version: 1\n", "version: 1\nextra: 1\n"},
		"version":          {"version: 1\n", "version: 2\n"},
		"unknown var key":  {"  - name: FLAG\n", "  - name: FLAG\n    colour: red\n"},
		"bad name":         {"name: FLAG", "name: 1FLAG"},
		"bad repo":         {"repo: owner/app", "repo: owner"},
		"unknown type":     {"type: env-file", "type: ftp"},
		"vercel no cred":   {", credential: vercel-deploy}", "}"},
		"vercel with repo": {"project: prj_1,", "project: prj_1, repo: a/b,"},
		"env-file no path": {"path: .env.local", "x: 1"},
		"no connection":    {"from: {connection: flags}", "from: {field: x}"},
		"http probe":       {"name: FLAG\n", "name: FLAG\n    verify: {url: http://x.test}\n"},
		"empty env list":   {"web: [production, preview]", "web: []"},
	} {
		doc := strings.Replace(goodManifest, tc[0], tc[1], 1)
		if doc == goodManifest {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if schema.Validate(generic(t, doc)) == nil {
			t.Errorf("%s: the schema accepts what the parser rejects", name)
		}
		if _, err := Parse([]byte(doc), nil); err == nil {
			t.Errorf("%s: the parser accepts it", name)
		}
	}
}
