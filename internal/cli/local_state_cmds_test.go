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
