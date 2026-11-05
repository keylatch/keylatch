package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadHarnessDrift(t *testing.T) {
	const valid = `{"harness":"claude-code","version":"2.0","result":"pass","checked_at":"2026-01-01T00:00:00Z","scope":"published-cli-config-reader"}`
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"valid", valid, true},
		{"failure", strings.Replace(valid, `"pass"`, `"fail"`, 1), true},
		{"wrong harness", strings.Replace(valid, "claude-code", "cursor", 1), false},
		{"wrong scope", strings.Replace(valid, "published-cli-config-reader", "sandbox", 1), false},
		{"future", strings.Replace(valid, "2026-01-01", "2999-01-01", 1), false},
		{"missing version", strings.Replace(valid, "2.0", "", 1), false},
		{"invalid result", strings.Replace(valid, `"pass"`, `"unknown"`, 1), false},
		{"invalid json", "{", false},
		{"too large", strings.Repeat(" ", 16385), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := ReadHarnessDrift(path, "claude-code")
			if (err == nil) != tc.valid {
				t.Fatalf("result=%+v error=%v", result, err)
			}
		})
	}
	if _, err := ReadHarnessDrift(filepath.Join(t.TempDir(), "missing"), "claude-code"); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := ReadHarnessDrift(t.TempDir(), "claude-code"); err == nil {
		t.Fatal("directory accepted")
	}
}
