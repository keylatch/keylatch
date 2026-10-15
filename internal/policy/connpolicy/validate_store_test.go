package connpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
)

func validDocument() Document {
	return Document{
		SchemaVersion: SchemaVersion,
		Connection:    "openrouter",
		Callers:       map[callerkind.Kind]CallerRule{callerkind.Human: {Allow: true}},
	}
}

// Validate holds the rules the schema cannot express, so each is checked on a
// document built in code.
func TestValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Document){
		"schema version":       func(d *Document) { d.SchemaVersion = 1 },
		"connection name":      func(d *Document) { d.Connection = "a/b" },
		"default":              func(d *Document) { d.Default = "allow" },
		"unparsable ttl":       func(d *Document) { d.MaxTTL = "soon" },
		"non-positive ttl":     func(d *Document) { d.MaxTTL = "-5m" },
		"capability glob":      func(d *Document) { d.Capabilities = []string{"["} },
		"caller kind":          func(d *Document) { d.Callers = map[callerkind.Kind]CallerRule{"root": {Allow: true}} },
		"runtime":              func(d *Document) { d.Callers[callerkind.Human] = CallerRule{Allow: true, Runtimes: []string{"warp"}} },
		"units on a human":     func(d *Document) { d.Callers[callerkind.Human] = CallerRule{Allow: true, Units: []string{"a.service"}} },
		"denied with runtimes": func(d *Document) { d.Callers[callerkind.Human] = CallerRule{Runtimes: []string{"gateway_typed"}} },
	} {
		d := validDocument()
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validDocument().Validate(); err != nil {
		t.Fatalf("a valid document was rejected: %v", err)
	}
}

func TestTTL(t *testing.T) {
	d := validDocument()
	if ttl, err := d.TTL(); err != nil || ttl != 0 {
		t.Fatalf("unset ttl = %v, %v", ttl, err)
	}
	d.MaxTTL = "15m"
	if ttl, err := d.TTL(); err != nil || ttl != 15*time.Minute {
		t.Fatalf("ttl = %v, %v", ttl, err)
	}
	d.MaxTTL = "nope"
	if _, err := d.TTL(); err == nil {
		t.Fatal("bad ttl accepted")
	}
}

func TestCallerRuleJSON(t *testing.T) {
	b, err := json.Marshal(CallerRule{})
	if err != nil || string(b) != `"deny"` {
		t.Fatalf("deny marshals to %s, %v", b, err)
	}
	b, err = json.Marshal(CallerRule{Allow: true, Runtimes: []string{"gateway_typed"}})
	if err != nil || !strings.Contains(string(b), `"allow":true`) {
		t.Fatalf("allow marshals to %s, %v", b, err)
	}
	var r CallerRule
	for _, bad := range []string{`"allow"`, `{"allow": true, "tiers": []}`, `5`} {
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := json.Unmarshal([]byte(`"deny"`), &r); err != nil || r.Allow {
		t.Fatalf("deny = %+v, %v", r, err)
	}
}

func TestParseReportsWhereADocumentIsWrong(t *testing.T) {
	_, err := Parse([]byte(`{"schema_version": 2, "connection": "a", "callers": {"agent": {"allow": "yes"}}}`))
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("error = %v", err)
	}
	if _, err := Parse([]byte(`not json`)); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectionOfFile(t *testing.T) {
	for name, want := range map[string]struct {
		conn string
		ok   bool
	}{
		"openrouter.json": {"openrouter", true},
		"_default.json":   {Fallback, true},
		"notes.txt":       {"", false},
		"a b.json":        {"a b", false},
	} {
		conn, ok := connectionOfFile(name)
		if conn != want.conn || ok != want.ok {
			t.Errorf("%s = %q, %v", name, conn, ok)
		}
	}
	if FileName(Fallback) != "_default.json" || FileName("a") != "a.json" {
		t.Fatal("FileName")
	}
}

func writeDoc(t *testing.T, dir, name, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRefusesWhatItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: dir}
	good := `{"schema_version": 2, "connection": "a", "callers": {"human": {"allow": true}}}`

	writeDoc(t, dir, "notes.txt", "ignored", 0o600)
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if docs, err := s.LoadAll(); err != nil || len(docs) != 0 {
		t.Fatalf("stray entries: %v, %v", docs, err)
	}
	if _, err := s.Load("sub"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory as document: %v", err)
	}
	if _, err := s.Load("bad/name"); err == nil {
		t.Fatal("invalid connection name accepted")
	}

	writeDoc(t, dir, "wrong.json", good, 0o600)
	if _, err := s.LoadAll(); err == nil || !strings.Contains(err.Error(), "belongs in") {
		t.Fatalf("misnamed file: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "wrong.json")); err != nil {
		t.Fatal(err)
	}

	writeDoc(t, dir, "b.json", good, 0o600)
	if _, err := s.Load("b"); err == nil || !strings.Contains(err.Error(), "names connection") {
		t.Fatalf("document for another connection: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "b.json")); err != nil {
		t.Fatal(err)
	}

	writeDoc(t, dir, "big.json", strings.Repeat(" ", maxDocumentSize+1), 0o600)
	if _, err := s.Load("big"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized document: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "big.json")); err != nil {
		t.Fatal(err)
	}

	writeDoc(t, dir, "broken.json", "{", 0o600)
	if _, err := s.LoadAll(); err == nil {
		t.Fatal("an invalid document was skipped instead of failing the read")
	}
}

func TestReplaceFailures(t *testing.T) {
	root := t.TempDir()

	blocker := filepath.Join(root, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Store{Dir: filepath.Join(blocker, "policy.d")}).Replace(map[string]Document{}); err == nil {
		t.Fatal("a store under a file was written")
	}

	// A document that cannot be marshalled stops the swap and keeps the old set.
	s := Store{Dir: filepath.Join(root, "policy.d")}
	if err := s.Replace(map[string]Document{"openrouter": validDocument()}); err != nil {
		t.Fatal(err)
	}
	bad := validDocument()
	bad.Callers = map[callerkind.Kind]CallerRule{callerkind.Human: {Allow: true}}
	if err := s.Replace(map[string]Document{"a/b": bad}); err == nil {
		t.Fatal("a document named with a path was written")
	}
	if docs, err := s.LoadAll(); err != nil || len(docs) != 1 {
		t.Fatalf("old set not kept: %v, %v", docs, err)
	}

	if err := writePrivate(filepath.Join(root, "policy.d", "openrouter.json"), []byte("x")); err == nil {
		t.Fatal("writePrivate overwrote an existing file")
	}
	if err := writePrivate(filepath.Join(root, "no-such-dir", "x.json"), []byte("x")); err == nil {
		t.Fatal("writePrivate wrote into a missing directory")
	}
}
