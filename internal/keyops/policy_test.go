package keyops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

var testMACKey = MACKey(bytes.Repeat([]byte{9}, 32))

func newStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "key-operations.json"), testMACKey)
}

func newAdmin(t *testing.T, s *Store) (*Admin, *captureAudit) {
	t.Helper()
	cap := &captureAudit{}
	a, err := NewAdmin(s, cap)
	if err != nil {
		t.Fatal(err)
	}
	return a, cap
}

func seeded(t *testing.T) (*Store, *Admin, *captureAudit) {
	t.Helper()
	s := newStore(t)
	a, cap := newAdmin(t, s)
	if err := a.Allow(context.Background(), human, Change{
		Connection: "app-local", Field: "RELEASE_SIGNING_KEY", Secret: "default/app/release",
		Operations: []string{"sign", "jwt_sign"}, Algorithms: []string{"Ed25519", "hmac-sha256"},
	}); err != nil {
		t.Fatal(err)
	}
	return s, a, cap
}

func TestStoreLookup(t *testing.T) {
	s, _, _ := seeded(t)
	ref, err := s.Lookup("app-local", "")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Field != "RELEASE_SIGNING_KEY" || ref.Policy.Algorithms[0] != EdDSA || ref.Policy.Algorithms[1] != HS256 {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if _, err := s.Lookup("other", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown connection: %v", err)
	}
	if _, err := s.Lookup("app-local", "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown field: %v", err)
	}
	if runtime.GOOS != "windows" { // Windows reports a fixed mode and has no permission bits to assert
		info, err := os.Stat(s.path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("allowlist mode: %v %v", info, err)
		}
	}
}

func TestStoreRequiresFieldWhenSeveral(t *testing.T) {
	s, a, _ := seeded(t)
	if err := a.Allow(context.Background(), human, Change{Connection: "app-local", Field: "OTHER", Secret: "x", Operations: []string{"sign"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("app-local", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ambiguous field: %v", err)
	}
}

func TestStoreMissingFileAllowsNothing(t *testing.T) {
	s := newStore(t)
	if _, err := s.Lookup("app-local", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if keys, err := s.SSHKeys(); err != nil || len(keys) != 0 {
		t.Fatalf("ssh keys: %v %v", keys, err)
	}
}

func TestStoreRejectsHandEditedFile(t *testing.T) {
	s, _, _ := seeded(t)
	raw, _ := os.ReadFile(s.path)

	edits := map[string]func([]byte) []byte{
		"widened operation": func(b []byte) []byte { return bytes.Replace(b, []byte(`"sign"`), []byte(`"decrypt"`), 1) },
		"changed secret": func(b []byte) []byte {
			return bytes.Replace(b, []byte("default/app/release"), []byte("default/other"), 1)
		},
		"dropped mac": func(b []byte) []byte { return bytes.Replace(b, []byte(`"mac":"`), []byte(`"mac":"00`), 1) },
		"not json":    func([]byte) []byte { return []byte("nope") },
		"bare policy": func([]byte) []byte { return []byte(`{"version":1,"connections":{}}`) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(s.path, edit(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := s.Lookup("app-local", "")
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "integrity check") {
				t.Fatalf("a hand-edited allowlist was trusted: %v", err)
			}
		})
	}

	_ = os.WriteFile(s.path, raw, 0o600)
	other := NewStore(s.path, MACKey(bytes.Repeat([]byte{1}, 32)))
	if _, err := other.Load(); !errors.Is(err, ErrTampered) {
		t.Fatalf("a file sealed by another installation was trusted: %v", err)
	}
	if runtime.GOOS != "windows" { // permission bits are not enforced on Windows
		_ = os.Chmod(s.path, 0o644)
		if _, err := s.Load(); err == nil {
			t.Fatal("a world-readable allowlist was loaded")
		}
	}
}

func TestStoreAcceptsReformatting(t *testing.T) {
	s, _, _ := seeded(t)
	raw, _ := os.ReadFile(s.path)
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, raw, "", "  ")
	_ = os.WriteFile(s.path, pretty.Bytes(), 0o600)
	if _, err := s.Load(); err != nil {
		t.Fatalf("whitespace changes should not break the seal: %v", err)
	}
}

func TestParsePolicyRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"unknown operation": `{"version":1,"connections":{"a":{"f":{"secret":"s","operations":["export"],"algorithms":[]}}}}`,
		"unknown algorithm": `{"version":1,"connections":{"a":{"f":{"secret":"s","operations":["sign"],"algorithms":["MD5"]}}}}`,
		"no secret":         `{"version":1,"connections":{"a":{"f":{"operations":["sign"],"algorithms":["HS256"]}}}}`,
		"unknown field":     `{"version":1,"connections":{},"extra":true}`,
		"wrong version":     `{"version":2,"connections":{}}`,
		"bad host key":      `{"version":1,"connections":{"a":{"f":{"secret":"s","operations":[],"algorithms":[],"ssh_agent":{"host_keys":["MD5:aa"]}}}}}`,
		"not json":          `[`,
	}
	for name, body := range cases {
		if _, err := ParsePolicy([]byte(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAllowIsHumanOnly(t *testing.T) {
	s, a, cap := seeded(t)
	before, _ := os.ReadFile(s.path)
	for _, c := range []Caller{{Kind: "agent", Constrained: true}, {Kind: "host", Constrained: true}} {
		err := a.Allow(context.Background(), c, Change{Connection: "app-local", Field: "RELEASE_SIGNING_KEY", Operations: []string{"decrypt"}, AgentDecrypt: true})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("%s allow: %v", c.Kind, err)
		}
	}
	after, _ := os.ReadFile(s.path)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused change modified the allowlist")
	}
	dump := cap.dump()
	for _, want := range []string{`"change":"allow"`, `"outcome":"denied"`, `"caller_kind":"agent"`, `"caller_kind":"host"`} {
		if !strings.Contains(dump, want) {
			t.Errorf("audit is missing %s: %s", want, dump)
		}
	}
}

func TestAllowMergesAndAuditsBeforeAfter(t *testing.T) {
	s, a, cap := seeded(t)
	err := a.Allow(context.Background(), human, Change{
		Connection: "app-local", Field: "RELEASE_SIGNING_KEY", Operations: []string{"verify", "sign"},
		Algorithms: []string{"ES256"}, SSHAgent: true, HostKeys: []string{"SHA256:abc"}, AgentDecrypt: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Lookup("app-local", "")
	fp := ref.Policy
	if strings.Join(fp.Operations, ",") != "sign,jwt_sign,verify" || strings.Join(fp.Algorithms, ",") != "EdDSA,HS256,ES256" ||
		!fp.AgentDecrypt || fp.SSHAgent == nil || fp.SSHAgent.HostKeys[0] != "SHA256:abc" || fp.Secret != "default/app/release" {
		t.Fatalf("unexpected merge: %+v", fp)
	}
	dump := cap.dump()
	if !strings.Contains(dump, `"before":"ops=sign,jwt_sign algs=EdDSA,HS256 agent_decrypt=false ssh_agent=none`) ||
		!strings.Contains(dump, `ops=sign,jwt_sign,verify algs=EdDSA,HS256,ES256 agent_decrypt=true ssh_agent=hosts:1`) {
		t.Fatalf("audit lacks before/after: %s", dump)
	}
	if strings.Contains(dump, "default/app/release") {
		t.Fatal("the backend path is in the audit trail")
	}
}

func TestAllowValidation(t *testing.T) {
	s := newStore(t)
	a, _ := newAdmin(t, s)
	ctx := context.Background()
	for name, ch := range map[string]Change{
		"no connection":   {Field: "F", Secret: "s"},
		"no field":        {Connection: "c", Secret: "s"},
		"no secret":       {Connection: "c", Field: "F", Operations: []string{"sign"}},
		"unknown op":      {Connection: "c", Field: "F", Secret: "s", Operations: []string{"export"}},
		"unknown alg":     {Connection: "c", Field: "F", Secret: "s", Algorithms: []string{"MD5"}},
		"bad fingerprint": {Connection: "c", Field: "F", Secret: "s", HostKeys: []string{"MD5:x"}},
	} {
		if err := a.Allow(ctx, human, ch); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(s.path); err == nil {
		t.Fatal("an invalid change wrote the allowlist")
	}
}

func TestAllowRefusesTamperedFile(t *testing.T) {
	s, a, _ := seeded(t)
	_ = os.WriteFile(s.path, []byte(`{"mac":"00","policy":{}}`), 0o600)
	if err := a.Allow(context.Background(), human, Change{Connection: "c", Field: "F", Secret: "s"}); !errors.Is(err, ErrTampered) {
		t.Fatalf("a change was layered on a tampered file: %v", err)
	}
}

func TestRevokeNarrowsForAnyCaller(t *testing.T) {
	s, a, cap := seeded(t)
	agentC := Caller{Kind: "agent", Constrained: true}
	ctx := context.Background()
	if err := a.Allow(ctx, human, Change{Connection: "app-local", Field: "RELEASE_SIGNING_KEY", AgentDecrypt: true, SSHAgent: true}); err != nil {
		t.Fatal(err)
	}
	err := a.Revoke(ctx, agentC, Change{Connection: "app-local", Field: "RELEASE_SIGNING_KEY",
		Operations: []string{"jwt_sign"}, Algorithms: []string{"hmac-sha256"}, AgentDecrypt: true, SSHAgent: true})
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Lookup("app-local", "")
	fp := ref.Policy
	if strings.Join(fp.Operations, ",") != "sign" || strings.Join(fp.Algorithms, ",") != "EdDSA" || fp.AgentDecrypt || fp.SSHAgent != nil {
		t.Fatalf("unexpected narrowing: %+v", fp)
	}
	if !strings.Contains(cap.dump(), `"change":"revoke"`) {
		t.Fatal("revoke is not audited")
	}

	if err := a.Revoke(ctx, agentC, Change{Connection: "app-local", Field: "RELEASE_SIGNING_KEY"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("app-local", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked connection still resolves: %v", err)
	}
}

func TestRevokeWholeConnectionAndErrors(t *testing.T) {
	s, a, _ := seeded(t)
	ctx := context.Background()
	_ = a.Allow(ctx, human, Change{Connection: "app-local", Field: "SECOND", Secret: "s2", Operations: []string{"sign"}})
	for name, ch := range map[string]Change{
		"no connection":        {},
		"narrow without field": {Connection: "app-local", Operations: []string{"sign"}},
		"host keys":            {Connection: "app-local", Field: "SECOND", HostKeys: []string{"SHA256:a"}},
		"secret":               {Connection: "app-local", Field: "SECOND", Secret: "x"},
		"unknown alg":          {Connection: "app-local", Field: "SECOND", Algorithms: []string{"MD5"}},
	} {
		if err := a.Revoke(ctx, human, ch); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := a.Revoke(ctx, human, Change{Connection: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown connection: %v", err)
	}
	if err := a.Revoke(ctx, human, Change{Connection: "app-local", Field: "NOPE"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown field: %v", err)
	}
	if err := a.Revoke(ctx, human, Change{Connection: "app-local"}); err != nil {
		t.Fatal(err)
	}
	doc, _ := s.Load()
	if len(doc) != 0 {
		t.Fatalf("connection was not removed: %v", doc)
	}
}

func TestAdminRollsBackWhenAuditFails(t *testing.T) {
	s, a, cap := seeded(t)
	before, _ := os.ReadFile(s.path)
	cap.fail = true
	if err := a.Allow(context.Background(), human, Change{Connection: "app-local", Field: "RELEASE_SIGNING_KEY", Operations: []string{"decrypt"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("allow with a broken audit log: %v", err)
	}
	if err := a.Revoke(context.Background(), human, Change{Connection: "app-local"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("revoke with a broken audit log: %v", err)
	}
	if _, err := s.Lookup("app-local", ""); err != nil {
		t.Fatalf("the allowlist changed without an audit record: %v", err)
	}
	_ = before
}

func TestListHidesSecretPathFromConstrainedCallers(t *testing.T) {
	_, a, _ := seeded(t)
	out, err := a.List(human, "")
	if err != nil || !strings.Contains(string(out), "default/app/release") {
		t.Fatalf("human list: %s %v", out, err)
	}
	out, err = a.List(Caller{Kind: "agent", Constrained: true}, "app-local")
	if err != nil || strings.Contains(string(out), "default/app/release") || !strings.Contains(string(out), "RELEASE_SIGNING_KEY") {
		t.Fatalf("agent list: %s %v", out, err)
	}
	if out, _ := a.List(human, "other"); strings.Contains(string(out), "app-local") {
		t.Fatal("list ignored the connection filter")
	}
	_ = os.WriteFile(a.store.path, []byte("x"), 0o600)
	if _, err := a.List(human, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("list over a tampered file: %v", err)
	}
}

func TestNewAdminRequiresArguments(t *testing.T) {
	if _, err := NewAdmin(nil, &captureAudit{}); err == nil {
		t.Fatal("no store")
	}
	if _, err := NewAdmin(newStore(t), nil); err == nil {
		t.Fatal("no emitter")
	}
	if _, err := NewAdmin(newStore(t), audit.Emitter(nil)); err == nil {
		t.Fatal("nil emitter")
	}
}

func TestInspectAndOpenStore(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
	if keys, present, err := Inspect(env); err != nil || present || keys != 0 {
		t.Fatalf("no allowlist: %d %v %v", keys, present, err)
	}
	store, err := OpenStore(env)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := newAdmin(t, store)
	if err := a.Allow(context.Background(), human, Change{Connection: "c", Field: "F", Secret: "s", Operations: []string{"sign"}}); err != nil {
		t.Fatal(err)
	}
	if keys, present, err := Inspect(env); err != nil || !present || keys != 1 {
		t.Fatalf("inspect: %d %v %v", keys, present, err)
	}
	again, err := OpenStore(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Load(); err != nil {
		t.Fatalf("a second open derives a different key: %v", err)
	}

	raw, _ := os.ReadFile(store.path)
	_ = os.WriteFile(store.path, bytes.Replace(raw, []byte(`"sign"`), []byte(`"decrypt"`), 1), 0o600)
	if _, present, err := Inspect(env); !present || !errors.Is(err, ErrTampered) {
		t.Fatalf("inspect did not flag a hand edit: %v", err)
	}

	_ = os.Remove(filepath.Join(dir, "audit-salt"))
	if _, _, err := Inspect(env); !errors.Is(err, ErrTampered) {
		t.Fatalf("inspect without the MAC key: %v", err)
	}
}

func TestOpenStoreRejectsShortSalt(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "audit-salt"), []byte("short"), 0o600)
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
	if _, err := OpenStore(env); err == nil {
		t.Fatal("a short salt was accepted")
	}
}

func TestNormalizeAlgorithm(t *testing.T) {
	for in, want := range map[string]string{
		"Ed25519": EdDSA, "eddsa": EdDSA, "AES-256-GCM": A256GCM, "hs256": HS256,
		"RSA-PSS": PS256, "RSA-PKCS1v15": RS256, "ECDSA-P384": ES384,
	} {
		if got, ok := NormalizeAlgorithm(in); !ok || got != want {
			t.Errorf("%s -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "none", "HS1", "RSA-OAEP"} {
		if _, ok := NormalizeAlgorithm(in); ok {
			t.Errorf("%q was accepted", in)
		}
	}
}
