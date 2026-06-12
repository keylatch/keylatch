package allow

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// clearRuleVars unsets every rule env var so ambient credentials in the test
// environment cannot leak signals into Suggest.
func clearRuleVars(t *testing.T) {
	t.Helper()
	for _, rule := range envVarRules {
		t.Setenv(rule.EnvVar, "")
	}
}

func TestSuggest_NoSignals(t *testing.T) {
	clearRuleVars(t)
	if got := Suggest(""); len(got) != 0 {
		t.Errorf("Suggest with no signals = %v, want empty", got)
	}
}

func TestSuggest_EnvOnlySignal(t *testing.T) {
	clearRuleVars(t)
	t.Setenv(envVarRules[0].EnvVar, "value-present")
	got := Suggest("")
	want := []string{envVarRules[0].Provider}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Suggest env-only = %v, want %v", got, want)
	}
}

func TestSuggest_TwoSignalsPreferred(t *testing.T) {
	clearRuleVars(t)
	// Two env signals; only the first also appears in the agent config, so
	// the 2-signal match must win and the env-only one must be dropped.
	t.Setenv(envVarRules[0].EnvVar, "x")
	t.Setenv(envVarRules[1].EnvVar, "y")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	cfg := `{"note": "uses ` + envVarRules[0].Provider + ` here"}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	got := Suggest(cfgPath)
	want := []string{envVarRules[0].Provider}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Suggest two-signal = %v, want %v", got, want)
	}
}

func TestSuggest_BadConfigIgnored(t *testing.T) {
	clearRuleVars(t)
	t.Setenv(envVarRules[0].EnvVar, "x")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(cfgPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Suggest(cfgPath)
	want := []string{envVarRules[0].Provider}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Suggest with bad config = %v, want %v", got, want)
	}
}

func TestContainsHelpers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello", "hello", true},
		{"hello", "nope", false},
		{"", "x", false},
		{"abc", "", true},
	}
	for _, tc := range cases {
		if got := contains(tc.s, tc.sub); got != tc.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
		}
	}
	if !stringContains("xyzzy", "zz") || stringContains("xy", "zz") {
		t.Error("stringContains basic cases failed")
	}
}

func TestDedup(t *testing.T) {
	t.Parallel()
	got := dedup([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedup = %v, want %v", got, want)
	}
}
