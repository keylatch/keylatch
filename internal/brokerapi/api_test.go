package brokerapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func frame(t *testing.T, r Request) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var proofHex = strings.Repeat("ab", ProofLen)

func validRequests() map[string]Request {
	files := map[string][]byte{"policy.json": []byte(`{}`), "policy.d/github.json": []byte(`{}`)}
	return map[string]Request{
		"status":   {Op: OpStatus},
		"set":      {Op: OpSecretSet, Path: "svc/key", Value: []byte("v"), Proof: proofHex},
		"delete":   {Op: OpSecretDelete, Path: "svc/key"},
		"list":     {Op: OpSecretList},
		"accept":   {Op: OpPolicyAccept, Files: files},
		"import":   {Op: OpPolicyImport, Bundle: &Bundle{Files: files, KeyID: "k", Signature: []byte("sig")}},
		"export":   {Op: OpPolicyExport},
		"check":    {Op: OpPolicyCheck},
		"head":     {Op: OpAuditHead},
		"rotate":   {Op: OpRotateKeys},
		"export-m": {Op: OpMigrateExport},
		"import-m": {Op: OpMigrateImport, Nonce: make([]byte, 16), Items: []Item{{Path: "a", Value: []byte("x")}}, OldAuditHead: "ab12"},
		"register": {Op: OpSessionRegister, Session: &SessionRequest{ID: "agent-12345", Cgroup: "/user.slice/x.scope"}},
		"end":      {Op: OpSessionEnd, Session: &SessionRequest{ID: "agent-12345"}},
		"verify":   {Op: OpSessionVerify, Ticket: "agent-12345.1.abcd"},
		"begin":    {Op: OpPresenceBegin, Target: &Request{Op: OpSecretDelete, Path: "svc/key"}},
	}
}

func TestDecodeAcceptsEveryOperation(t *testing.T) {
	for name, req := range validRequests() {
		t.Run(name, func(t *testing.T) {
			got, err := Decode(frame(t, req))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got.Op != req.Op || got.Digest() != req.Digest() {
				t.Fatal("a round trip changed the request")
			}
			if op, ok := OpOf(frame(t, req)); !ok || op != req.Op {
				t.Fatalf("OpOf = %q %v", op, ok)
			}
		})
	}
}

func TestDecodeRefusesMalformed(t *testing.T) {
	good := validRequests()
	cases := map[string][]byte{
		"empty":            nil,
		"not json":         []byte("nope"),
		"unknown field":    []byte(`{"op":"broker.status","extra":1}`),
		"unknown op":       []byte(`{"op":"broker.nothing"}`),
		"control op":       []byte(`{"op":"exec"}`),
		"trailing":         []byte(`{"op":"broker.status"}{"op":"broker.status"}`),
		"short proof":      []byte(`{"op":"secret.delete","path":"a","proof":"abcd"}`),
		"non-hex proof":    []byte(`{"op":"secret.delete","path":"a","proof":"` + strings.Repeat("zz", ProofLen) + `"}`),
		"set without path": []byte(`{"op":"secret.set"}`),
		"nul in path":      frame(t, Request{Op: OpSecretDelete, Path: "a\x00b"}),
		"huge path":        frame(t, Request{Op: OpSecretDelete, Path: strings.Repeat("a", MaxPathLen+1)}),
		"huge value":       frame(t, Request{Op: OpSecretSet, Path: "a", Value: make([]byte, MaxValue+1)}),
		"policy no files":  frame(t, Request{Op: OpPolicyAccept}),
		"policy no root":   frame(t, Request{Op: OpPolicyAccept, Files: map[string][]byte{"policy.d/x.json": {}}}),
		"policy bad name":  frame(t, Request{Op: OpPolicyAccept, Files: map[string][]byte{"policy.json": {}, "../etc/passwd": {}}}),
		"policy big file":  frame(t, Request{Op: OpPolicyAccept, Files: map[string][]byte{"policy.json": make([]byte, MaxFileSize+1)}}),
		"import no bundle": frame(t, Request{Op: OpPolicyImport}),
		"import bad files": frame(t, Request{Op: OpPolicyImport, Bundle: &Bundle{Files: map[string][]byte{"x": {}}}}),
		"import big sig":   frame(t, Request{Op: OpPolicyImport, Bundle: &Bundle{Files: good["accept"].Files, Signature: make([]byte, 200)}}),
		"begin no target":  frame(t, Request{Op: OpPresenceBegin}),
		"begin read-only":  frame(t, Request{Op: OpPresenceBegin, Target: &Request{Op: OpStatus}}),
		"begin nested":     frame(t, Request{Op: OpPresenceBegin, Target: &Request{Op: OpPresenceBegin, Target: &Request{Op: OpRotateKeys}}}),
		"begin with proof": frame(t, Request{Op: OpPresenceBegin, Target: &Request{Op: OpRotateKeys, Proof: proofHex}}),
		"target elsewhere": frame(t, Request{Op: OpStatus, Target: &Request{Op: OpRotateKeys}}),
		"target invalid":   frame(t, Request{Op: OpPresenceBegin, Target: &Request{Op: OpSecretSet}}),
		"migrate no nonce": frame(t, Request{Op: OpMigrateImport}),
		"migrate dup":      frame(t, Request{Op: OpMigrateImport, Nonce: make([]byte, 16), Items: []Item{{Path: "a"}, {Path: "a"}}}),
		"migrate bad path": frame(t, Request{Op: OpMigrateImport, Nonce: make([]byte, 16), Items: []Item{{Path: ""}}}),
		"migrate big item": frame(t, Request{Op: OpMigrateImport, Nonce: make([]byte, 16), Items: []Item{{Path: "a", Value: make([]byte, MaxValue+1)}}}),
		"migrate bad head": frame(t, Request{Op: OpMigrateImport, Nonce: make([]byte, 16), OldAuditHead: "xyz"}),
		"many signals":     frame(t, Request{Op: OpStatus, Signals: make([]string, 65)}),
		"long signal":      frame(t, Request{Op: OpStatus, Signals: []string{strings.Repeat("s", 129)}}),
		"long ticket":      frame(t, Request{Op: OpStatus, Ticket: strings.Repeat("t", 513)}),
		"verify no ticket": frame(t, Request{Op: OpSessionVerify}),
		"session no id":    frame(t, Request{Op: OpSessionRegister}),
		"session bad id":   frame(t, Request{Op: OpSessionRegister, Session: &SessionRequest{ID: "a b"}}),
		"session bad cg":   frame(t, Request{Op: OpSessionRegister, Session: &SessionRequest{ID: "agent-12345", Cgroup: "a\x00"}}),
	}
	items := make([]Item, MaxItems+1)
	for i := range items {
		items[i] = Item{Path: "p" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + strings.Repeat("y", i/26%20) + string(rune('a'+i/520%26))}
	}
	cases["migrate too many"] = frame(t, Request{Op: OpMigrateImport, Nonce: make([]byte, 16), Items: items})

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(raw); !errors.Is(err, ErrBadRequest) {
				t.Fatalf("Decode = %v, want ErrBadRequest", err)
			}
		})
	}
	if _, ok := OpOf([]byte(`{"op":"exec"}`)); ok {
		t.Fatal("OpOf must reject control operations")
	}
	if _, ok := OpOf([]byte("garbage")); ok {
		t.Fatal("OpOf must reject garbage")
	}
}

func TestPrivileged(t *testing.T) {
	for _, op := range []Op{OpPolicyAccept, OpPolicyImport, OpSecretSet, OpSecretDelete, OpMigrateImport, OpMigrateExport, OpRotateKeys} {
		if !Privileged(op) {
			t.Errorf("%s must be privileged", op)
		}
	}
	for _, op := range []Op{OpStatus, OpPresenceBegin, OpPolicyExport, OpPolicyCheck, OpSecretList, OpAuditHead, OpSessionRegister, OpSessionEnd} {
		if Privileged(op) {
			t.Errorf("%s must not be privileged", op)
		}
	}
}

func TestDigestBindsEveryField(t *testing.T) {
	base := Request{Op: OpSecretSet, Path: "a", Value: []byte("v")}
	variants := map[string]Request{
		"op":     {Op: OpSecretDelete, Path: "a", Value: []byte("v")},
		"path":   {Op: OpSecretSet, Path: "b", Value: []byte("v")},
		"value":  {Op: OpSecretSet, Path: "a", Value: []byte("w")},
		"files":  {Op: OpSecretSet, Path: "a", Value: []byte("v"), Files: map[string][]byte{"policy.json": []byte("x")}},
		"bundle": {Op: OpSecretSet, Path: "a", Value: []byte("v"), Bundle: &Bundle{Files: map[string][]byte{"policy.json": []byte("x")}}},
		"items":  {Op: OpSecretSet, Path: "a", Value: []byte("v"), Items: []Item{{Path: "x", Value: []byte("y")}}},
		"nonce":  {Op: OpSecretSet, Path: "a", Value: []byte("v"), Nonce: []byte("n")},
		"head":   {Op: OpSecretSet, Path: "a", Value: []byte("v"), OldAuditHead: "ab"},
	}
	d := base.Digest()
	for name, v := range variants {
		if v.Digest() == d {
			t.Errorf("digest ignores %s", name)
		}
	}
	withProof := base
	withProof.Proof = proofHex
	if withProof.Digest() != d {
		t.Error("the proof must not be part of the digest it is issued for")
	}
	a := Request{Op: OpMigrateImport, Items: []Item{{Path: "a", Value: []byte("1")}, {Path: "b", Value: []byte("2")}}}
	b := Request{Op: OpMigrateImport, Items: []Item{{Path: "b", Value: []byte("2")}, {Path: "a", Value: []byte("1")}}}
	if a.Digest() != b.Digest() {
		t.Error("item order must not change the digest")
	}
	// Length prefixes keep field boundaries unambiguous.
	if (Request{Op: OpSecretSet, Path: "ab"}).Digest() == (Request{Op: OpSecretSet, Path: "a", Nonce: []byte("b")}).Digest() {
		t.Error("field boundaries are ambiguous")
	}
}

func TestDescribeNamesTheRequest(t *testing.T) {
	for _, tc := range []struct {
		req    Request
		action string
		want   string
	}{
		{Request{Op: OpSecretSet, Path: "svc/key", Value: []byte("abc")}, "secret.set", `3-byte secret at "svc/key"`},
		{Request{Op: OpSecretDelete, Path: "svc/key"}, "secret.delete", `"svc/key"`},
		{Request{Op: OpPolicyAccept, Files: map[string][]byte{"policy.json": nil}}, "policy.change", "1 file"},
		{Request{Op: OpPolicyImport, Bundle: &Bundle{Files: map[string][]byte{"policy.json": nil}}}, "policy.change", "another host"},
		{Request{Op: OpPolicyImport}, "policy.change", "0 file"},
		{Request{Op: OpMigrateImport, Items: []Item{{Path: "a"}}}, "broker.adopt", "1 secret"},
		{Request{Op: OpMigrateExport}, "broker.export", "back into your account"},
		{Request{Op: OpRotateKeys}, "keys.rotate", "master key"},
		{Request{Op: OpStatus}, "broker.status", "broker.status"},
	} {
		action, summary := tc.req.Describe()
		if action != tc.action || !strings.Contains(summary, tc.want) || !strings.Contains(summary, tc.req.Digest()[:12]) {
			t.Errorf("Describe(%s) = %q, %q", tc.req.Op, action, summary)
		}
	}
}
