package connpolicy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/callerkind"
)

func mustParse(t *testing.T, s string) Document {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, s)
	}
	return d
}

const agentGateway = `{
  "schema_version": 2,
  "connection": "openrouter",
  "default": "deny",
  "max_ttl": "15m",
  "capabilities": ["inject", "openrouter.*"],
  "callers": {
    "agent": {"allow": true, "runtimes": ["gateway_typed", "gateway_sdk"], "exe": ["python3", "/usr/bin/node"]},
    "service": {"allow": true, "units": ["deploy.service"]},
    "host": "deny"
  }
}`

func TestParseRejectsInvalidDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":              `{`,
		"missing connection":    `{"schema_version": 2}`,
		"wrong version":         `{"schema_version": 1, "connection": "a"}`,
		"unknown key":           `{"schema_version": 2, "connection": "a", "allow": true}`,
		"default allow":         `{"schema_version": 2, "connection": "a", "default": "allow"}`,
		"bad connection name":   `{"schema_version": 2, "connection": "../x"}`,
		"unknown caller kind":   `{"schema_version": 2, "connection": "a", "callers": {"root": "deny"}}`,
		"rule string not deny":  `{"schema_version": 2, "connection": "a", "callers": {"agent": "allow"}}`,
		"rule unknown key":      `{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": true, "bogus": ["D1"]}}}`,
		"rule without allow":    `{"schema_version": 2, "connection": "a", "callers": {"agent": {"runtimes": ["gateway_typed"]}}}`,
		"unknown runtime":       `{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": true, "runtimes": ["warp_drive"]}}}`,
		"empty runtimes":        `{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": true, "runtimes": []}}}`,
		"units on an agent":     `{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": true, "units": ["x.service"]}}}`,
		"denied with a list":    `{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": false, "runtimes": ["gateway_typed"]}}}`,
		"bad ttl":               `{"schema_version": 2, "connection": "a", "max_ttl": "soon"}`,
		"zero ttl":              `{"schema_version": 2, "connection": "a", "max_ttl": "0s"}`,
		"duplicate capability":  `{"schema_version": 2, "connection": "a", "capabilities": ["x", "x"]}`,
		"unit without .service": `{"schema_version": 2, "connection": "a", "callers": {"service": {"allow": true, "units": ["nginx"]}}}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecide(t *testing.T) {
	d := mustParse(t, agentGateway)
	for _, tc := range []struct {
		name  string
		req   Request
		allow bool
		why   string
	}{
		{"agent under a listed runtime", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent}, true, ""},
		{"agent under the other listed runtime", Request{Action: "openrouter.chat", Runtime: "gateway_sdk", Caller: callerkind.Agent}, true, ""},
		{"agent under an unlisted runtime", Request{Action: "inject", Runtime: "minted", Caller: callerkind.Agent}, false, "only under gateway_typed, gateway_sdk, not minted"},
		{"agent without a runtime", Request{Action: "call", Caller: callerkind.Agent}, false, "no runtime"},
		{"agent with a listed executable", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent, Command: []string{"python3", "x.py"}}, true, ""},
		{"agent with a listed path", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent, Command: []string{"/usr/bin/node"}}, true, ""},
		{"agent base name of a listed path is not enough", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent, Command: []string{"node"}}, false, "does not allow"},
		{"agent with another executable", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent, Command: []string{"curl"}}, false, "does not allow"},
		{"agent with a path ending in a listed name", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent, Command: []string{"/tmp/evil/python3"}}, false, "does not allow"},
		{"capability outside the list", Request{Action: "github.repos", Runtime: "gateway_typed", Caller: callerkind.Agent}, false, "capability"},
		{"host is denied", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Host}, false, "denies host"},
		{"human has no entry", Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Human}, false, "no callers.human"},
		{"service in its unit", Request{Action: "inject", Caller: callerkind.Service, Unit: "deploy.service"}, true, ""},
		{"service in another unit", Request{Action: "inject", Caller: callerkind.Service, Unit: "other.service"}, false, "only in deploy.service"},
		{"service with no unit", Request{Action: "inject", Caller: callerkind.Service}, false, "only in deploy.service"},
		{"unknown kind", Request{Action: "inject", Caller: "root"}, false, "no callers.root"},
	} {
		got := d.Decide(tc.req)
		if got.Allow != tc.allow || (tc.why != "" && !strings.Contains(got.Reason, tc.why)) {
			t.Errorf("%s: allow=%v reason=%q, want allow=%v containing %q", tc.name, got.Allow, got.Reason, tc.allow, tc.why)
		}
	}
	if got := d.Decide(Request{Action: "inject", Runtime: "gateway_typed", Caller: callerkind.Agent}); got.MaxTTL.Minutes() != 15 {
		t.Errorf("max ttl = %v, want 15m", got.MaxTTL)
	}
}

// A connection that mentions no caller kind denies all of them.
func TestDecideDefaultsToDeny(t *testing.T) {
	d := mustParse(t, `{"schema_version": 2, "connection": "a"}`)
	for _, k := range Kinds {
		if d.Decide(Request{Action: "inject", Caller: k}).Allow {
			t.Errorf("%s allowed by a document with no callers", k)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	d := mustParse(t, agentGateway)
	b, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	again := mustParse(t, string(b))
	if Describe(d) != Describe(again) {
		t.Fatalf("round trip changed the document:\n%s\n%s", Describe(d), Describe(again))
	}
	if !strings.Contains(string(b), `"host": "deny"`) {
		t.Errorf("a denied caller is not written as \"deny\":\n%s", b)
	}
}

func TestStoreLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy.d")
	s := Store{Dir: dir}
	if d, err := s.Load("openrouter"); d != nil || err != nil {
		t.Fatalf("missing store: %v, %v", d, err)
	}

	doc := mustParse(t, agentGateway)
	if err := s.Replace(map[string]Document{"openrouter": doc}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("openrouter")
	if err != nil || got == nil || Describe(*got) != Describe(doc) {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if d, err := s.Load("other"); d != nil || err != nil {
		t.Fatalf("unrelated connection: %v, %v", d, err)
	}
	if _, err := s.Load("../etc"); err == nil {
		t.Fatal("path traversal accepted as a connection name")
	}

	// A document under the wrong name is refused rather than misapplied.
	data, _ := os.ReadFile(filepath.Join(dir, "openrouter.json"))
	if err := os.WriteFile(filepath.Join(dir, "vercel.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("vercel"); err == nil || !strings.Contains(err.Error(), "names connection") {
		t.Fatalf("misnamed document: %v", err)
	}
	if _, err := s.LoadAll(); err == nil {
		t.Fatal("LoadAll accepted a misnamed document")
	}
}

func TestStoreRefusesUnsafeFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy.d")
	s := Store{Dir: dir}
	if err := s.Replace(map[string]Document{"openrouter": mustParse(t, agentGateway)}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "openrouter.json")
	if runtime.GOOS != "windows" { // the store does not check permission bits on Windows
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load("openrouter"); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
			t.Fatalf("group- and world-writable document: %v", err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"schema_version": 2, "connection": "openrouter", "default": "allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("openrouter"); err == nil {
		t.Fatal("invalid document loaded")
	}
}

func TestReplaceIsAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy.d")
	s := Store{Dir: dir}
	old := map[string]Document{"openrouter": mustParse(t, agentGateway)}
	if err := s.Replace(old); err != nil {
		t.Fatal(err)
	}
	fallback := mustParse(t, `{"schema_version": 2, "connection": "*", "callers": {"human": {"allow": true}}}`)
	if err := s.Replace(map[string]Document{"*": fallback}); err != nil {
		t.Fatal(err)
	}
	all, err := s.LoadAll()
	if err != nil || len(all) != 1 || all["*"].Connection != "*" {
		t.Fatalf("after replace: %v, %v", all, err)
	}
	if _, err := os.Stat(dir + ".old"); err == nil {
		t.Fatal("the previous set was left behind")
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".policy.d-new-") {
			t.Fatalf("staging directory %s left behind", e.Name())
		}
	}
}

func TestReadDirDuplicatesAndArbitraryNames(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a-any-name.json", agentGateway)
	write("notes.txt", "ignored")
	docs, err := ReadDir(dir, false)
	if err != nil || len(docs) != 1 || docs["openrouter"].Connection != "openrouter" {
		t.Fatalf("ReadDir = %v, %v", docs, err)
	}
	write("b-copy.json", agentGateway)
	if _, err := ReadDir(dir, false); err == nil || !strings.Contains(err.Error(), "second document") {
		t.Fatalf("duplicate connection: %v", err)
	}
}

func TestDiff(t *testing.T) {
	a := mustParse(t, agentGateway)
	b := mustParse(t, `{"schema_version": 2, "connection": "openrouter", "callers": {"human": {"allow": true}}}`)
	c := mustParse(t, `{"schema_version": 2, "connection": "stripe", "callers": {"human": {"allow": true}}}`)

	if lines := Diff(map[string]Document{"openrouter": a}, map[string]Document{"openrouter": a}); len(lines) != 0 {
		t.Fatalf("equal sets differ: %v", lines)
	}
	lines := Diff(map[string]Document{"openrouter": a}, map[string]Document{"openrouter": b, "stripe": c})
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "~ openrouter: ") || !strings.HasPrefix(lines[1], "+ stripe: ") {
		t.Fatalf("diff = %q", lines)
	}
	if got := Diff(map[string]Document{"stripe": c}, nil); len(got) != 1 || !strings.HasPrefix(got[0], "- stripe: ") {
		t.Fatalf("removal = %q", got)
	}
}
