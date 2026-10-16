package sync

import (
	"strings"
	"testing"
)

func TestSummaryNamesWhereSecretsGo(t *testing.T) {
	raw := []byte(`version: 1
targets:
  web: {type: vercel, project: prj_1, team: team_a, credential: vercel-deploy}
  repo: {type: github-actions, repo: octo/app, environments: [production], credential: gh-admin}
  local: {type: env-file, path: .env.local}
vars:
  - name: API_KEY
    from: {connection: openai, field: api_key}
    to: {web: [production], repo: [production], local: [file]}
    verify: {url: "https://Api.Example.test/v1/me"}
`)
	got := Summarize(raw, "", "")
	for _, want := range []string{
		"API_KEY<-openai.api_key", "project prj_1", "team team_a", "credential vercel-deploy",
		"repo octo/app", "credential gh-admin", "path .env.local", "verified against api.example.test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q lacks %q", got, want)
		}
	}
	if only := Summarize(raw, "API_KEY", "local"); strings.Contains(only, "octo/app") || !strings.Contains(only, ".env.local") {
		t.Errorf("a one-target summary = %q", only)
	}
	if got := Summarize([]byte("nope: ["), "", ""); !strings.Contains(got, "does not validate") {
		t.Errorf("invalid manifest = %q", got)
	}
}

func TestVerifyHostKeepsAnUnparsableURLVisible(t *testing.T) {
	if got := VerifyHost("https://A.test:8443/x"); got != "a.test:8443" {
		t.Fatalf("host = %q", got)
	}
	if got := VerifyHost("::bad"); got != "::bad" {
		t.Fatalf("unparsable = %q", got)
	}
}
