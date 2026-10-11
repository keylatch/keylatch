package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway"
)

func cdRulesEnv(p string) func(string) string {
	return func(k string) string {
		if k == "KEYLATCH_GATEWAY_RULES" {
			return p
		}
		return ""
	}
}

func TestRules_DeleteKeepsOtherRules(t *testing.T) {
	dir := cdIsolate(t)
	p := filepath.Join(dir, "rules.json")
	t.Setenv("KEYLATCH_GATEWAY_RULES", p)
	for _, a := range []string{"chat", "embed"} {
		if r := cdExec(t, newRulesCmd(), nil, "create", "--provider", "openai", "--action", a, "--block"); r.e != nil {
			t.Fatal(r.e)
		}
	}
	rules, err := loadGatewayRules(cdRulesEnv(p))
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	r := cdExec(t, newRulesCmd(), nil, "delete", rules[0].ID)
	if r.e != nil || !strings.Contains(r.out, "rule deleted: "+rules[0].ID) {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
	left, _ := loadGatewayRules(cdRulesEnv(p))
	if len(left) != 1 || left[0].ID != rules[1].ID || left[0].Action != "embed" {
		t.Fatalf("unexpected remaining rules %+v", left)
	}
}

func TestRules_UnreadableStoreFailsEveryCommand(t *testing.T) {
	dir := cdIsolate(t)
	p := filepath.Join(dir, "rules-dir")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_GATEWAY_RULES", p)
	for _, args := range [][]string{
		{"list"},
		{"create", "--provider", "openai", "--action", "chat", "--block"},
		{"delete", "rule_x"},
	} {
		if r := cdExec(t, newRulesCmd(), nil, args...); r.e == nil || !strings.Contains(r.e.Error(), "rules: read") {
			t.Fatalf("%v: err = %v", args, r.e)
		}
	}
}

func TestRules_SaveFailures(t *testing.T) {
	dir := cdIsolate(t)
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveGatewayRules(cdRulesEnv(filepath.Join(blocker, "rules.json")), nil); err == nil || !strings.Contains(err.Error(), "rules: mkdir") {
		t.Fatalf("mkdir under a file: %v", err)
	}

	target := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveGatewayRules(cdRulesEnv(target), nil); err == nil || !strings.Contains(err.Error(), "rules: rename") {
		t.Fatalf("rename over a directory: %v", err)
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file must be cleaned up after a failed rename")
	}
	if err := saveGatewayRules(cdRulesEnv(filepath.Join(target+".tmpdir-missing", "r.json")), nil); err != nil {
		t.Fatalf("save must create parent dirs: %v", err)
	}
}

func TestRules_DeleteSaveFailureKeepsRule(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions enforced for a non-root user")
	}
	dir := cdIsolate(t)
	sub := filepath.Join(dir, "rules")
	p := filepath.Join(sub, "rules.json")
	t.Setenv("KEYLATCH_GATEWAY_RULES", p)
	if r := cdExec(t, newRulesCmd(), nil, "create", "--provider", "openai", "--action", "chat", "--block"); r.e != nil {
		t.Fatal(r.e)
	}
	rules, _ := loadGatewayRules(cdRulesEnv(p))
	if err := os.Chmod(sub, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	r := cdExec(t, newRulesCmd(), nil, "delete", rules[0].ID)
	if r.e == nil || !strings.Contains(r.e.Error(), "rules delete: save") {
		t.Fatalf("err = %v", r.e)
	}
	if left, _ := loadGatewayRules(cdRulesEnv(p)); len(left) != 1 {
		t.Fatal("rule must survive a failed delete")
	}
}

// cdFakeBwrap puts an executable named bwrap first on PATH.
func cdFakeBwrap(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("bwrap detection is Linux-only")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // fake executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func cdNoBwrap(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("bwrap detection is Linux-only")
	}
	for _, p := range []string{"/usr/bin/bwrap", "/usr/local/bin/bwrap"} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("%s is installed on this host", p)
		}
	}
	t.Setenv("PATH", t.TempDir())
}

func TestModes_AllAvailableExitsZero(t *testing.T) {
	dir := cdIsolate(t)
	cdFakeBwrap(t)
	gwPID := filepath.Join(dir, "gateway.pid")
	t.Setenv("KEYLATCH_GATEWAY_PID", gwPID)
	for _, p := range []string{gwPID, proxyPIDPathFromDir(dir)} {
		if err := gateway.WritePID(p, os.Getpid()); err != nil {
			t.Fatal(err)
		}
	}

	r := cdExec(t, newModesCmd(), nil, "--json")
	if r.e != nil {
		t.Fatalf("all modes available must exit zero: %v", r.e)
	}
	var doc struct {
		Modes []ModeEntry `json:"modes"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil || len(doc.Modes) == 0 {
		t.Fatalf("json: %v %q", err, r.out)
	}
	for _, m := range doc.Modes {
		if !m.Available || m.Reason != "" && !strings.HasPrefix(m.Reason, "bwrap found") || m.Fix != "" {
			t.Fatalf("mode %+v should be available with no fix", m)
		}
	}

	r = cdExec(t, newModesCmd(), nil)
	if r.e != nil || strings.Contains(r.out, "not running") {
		t.Fatalf("table: err=%v out=%q", r.e, r.out)
	}
}

func TestModes_MissingBwrapIsReported(t *testing.T) {
	cdIsolate(t)
	cdNoBwrap(t)
	ok, reason, fix := sandboxModeAvailability()
	if ok || !strings.Contains(reason, "not found") || !strings.Contains(fix, "bubblewrap") {
		t.Fatalf("got %v %q %q", ok, reason, fix)
	}
}

func TestSandbox_RunWithBwrapIsNotImplemented(t *testing.T) {
	cdFakeBwrap(t)
	r := cdExec(t, newSandboxCmd(), nil, "run", "--connection", "openai", "--", "env")
	if r.e == nil || !strings.Contains(r.e.Error(), "not yet implemented") ||
		!strings.Contains(r.e.Error(), "direct_classic_sandboxed openai -- env") {
		t.Fatalf("err = %v", r.e)
	}
}

func TestSandbox_WithoutBwrap(t *testing.T) {
	cdNoBwrap(t)
	r := cdExec(t, newSandboxCmd(), nil, "run", "--connection", "openai", "--", "env")
	if r.e == nil || !strings.Contains(r.e.Error(), "bwrap not found") {
		t.Fatalf("run: err = %v", r.e)
	}
	r = cdExec(t, newSandboxCmd(), nil, "doctor")
	if r.e != nil || !strings.Contains(r.out, "not available") {
		t.Fatalf("doctor: err=%v out=%q", r.e, r.out)
	}
}

var cdProviderEnvVars = []string{
	"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "STRIPE_SECRET_KEY", "SLACK_BOT_TOKEN",
	"OPENROUTER_API_KEY", "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "COHERE_API_KEY", "MISTRAL_API_KEY",
	"GEMINI_API_KEY", "HUGGINGFACE_TOKEN", "REPLICATE_API_TOKEN", "ELEVENLABS_API_KEY", "CLOUDFLARE_API_TOKEN",
	"SUPABASE_SERVICE_ROLE_KEY", "TURSO_AUTH_TOKEN", "PINECONE_API_KEY", "WEAVIATE_API_KEY", "RESEND_API_KEY",
	"SENDGRID_API_KEY",
}

func cdClearProviderEnv(t *testing.T) {
	t.Helper()
	for _, k := range cdProviderEnvVars {
		t.Setenv(k, "")
	}
}

func TestAllowSuggestEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     []string
		stdin   string
		want    string
		notWant string
	}{
		{name: "nothing detected", want: "No providers detected from environment variables."},
		{name: "accept all", env: []string{"OPENAI_API_KEY"}, stdin: "y\n", want: "Adding all: openai"},
		{name: "decline", env: []string{"OPENAI_API_KEY"}, stdin: "N\n", want: "Skipped."},
		{name: "no answer", env: []string{"OPENAI_API_KEY"}, stdin: "", want: "Skipped."},
		{name: "select subset", env: []string{"OPENAI_API_KEY", "GITHUB_TOKEN"}, stdin: "github,openai\n", want: "Adding selected: github, openai"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			cdClearProviderEnv(t)
			for _, k := range tc.env {
				t.Setenv(k, "set")
			}
			r := cdExec(t, newAllowCmd(), strings.NewReader(tc.stdin), "--suggest-env")
			if r.e != nil || !strings.Contains(r.out, tc.want) {
				t.Fatalf("err=%v out=%q want %q", r.e, r.out, tc.want)
			}
			if strings.Contains(r.out, "set") && !strings.Contains(r.out, "Suggested") {
				t.Fatalf("env values must not be echoed: %q", r.out)
			}
		})
	}
}

func TestAllowSuggestEnv_PrefersProvidersConfirmedByAgentConfig(t *testing.T) {
	home := cdIsolate(t)
	cdClearProviderEnv(t)
	t.Setenv("OPENAI_API_KEY", "set")
	t.Setenv("ANTHROPIC_API_KEY", "set")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"model":"anthropic/claude"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := cdExec(t, newAllowCmd(), strings.NewReader("y\n"), "--suggest-env")
	if r.e != nil || !strings.Contains(r.out, "based on your environment: anthropic.") || strings.Contains(r.out, "openai") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
}
