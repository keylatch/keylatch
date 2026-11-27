package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzPolicyParse loads arbitrary bytes as a policy file. Loading must not
// panic, and a policy that loads must decide any request without panicking.
func FuzzPolicyParse(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"default_deny":true,"rules":[]}`))
	f.Add([]byte(`{"default_deny":false,"rules":[{"id":"r","actor":"*","connections":["*"],"capabilities":["*"]}]}`))
	f.Add([]byte(`{"rules":[{"runtime":"bogus"}]}`))
	f.Add([]byte(`{"rules":[{"rate_limit":{"max_calls":1}}]}`))
	f.Add([]byte(`{"rules":`))
	f.Add([]byte("\x00"))

	path := filepath.Join(f.TempDir(), "policy.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip(err)
		}
		p, err := Load(path)
		if err != nil {
			return
		}
		for _, req := range []Request{
			{},
			{Actor: "agent", Connection: "github", Capability: "read", LLMSession: true},
			{Actor: "*", Connection: "*", Capability: "*", Command: []string{"x"}, CWD: "/"},
		} {
			_ = p.Check(req)
		}
	})
}
