package ci_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/config"
)

func TestSessionRoundTripAndScope(t *testing.T) {
	now := time.Now()
	tr := config.CITrust{Connections: []string{"github-app"}, MaxTTL: 600}
	s := ci.NewSession(ci.Identity{Provider: ci.GitHubActions, Repository: "acme/app", Ref: "refs/heads/main", Expiry: now.Add(time.Hour)}, tr, now)
	if got := s.Expires.Sub(now); got > 600*time.Second || got < 599*time.Second {
		t.Fatalf("session lifetime %v, want the trust entry's 600s", got)
	}
	short := ci.NewSession(ci.Identity{Expiry: now.Add(time.Minute)}, config.CITrust{Connections: []string{"c"}}, now)
	if short.Expires.Sub(now) > time.Minute {
		t.Fatalf("session outlives the token: %v", short.Expires)
	}

	path, err := ci.WriteSession(filepath.Join(t.TempDir(), "nested"), s)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Fatalf("session file: %v %v", info, err)
	}
	back, err := ci.ReadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Allows("github-app", now) || back.Allows("other", now) || back.Allows("github-app", now.Add(time.Hour)) {
		t.Fatalf("scope wrong: %+v", back)
	}
}

func TestReadSessionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"garbage": "{", "empty": `{"connections":[],"expires":"2030-01-01T00:00:00Z"}`, "no expiry": `{"connections":["c"]}`} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ci.ReadSession(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := ci.ReadSession(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing: want an error")
	}
}

func TestSessionDirPrefersRunnerTemp(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if got := ci.SessionDir(get(map[string]string{"RUNNER_TEMP": "/r"})); got != filepath.Join("/r", "keylatch") {
		t.Fatalf("got %q", got)
	}
	if got := ci.SessionDir(get(nil)); !strings.HasPrefix(got, os.TempDir()) {
		t.Fatalf("got %q", got)
	}
}

func TestExportEnv(t *testing.T) {
	f := filepath.Join(t.TempDir(), "env")
	if err := ci.ExportEnv(f, "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := ci.ExportEnv(f, "B", "2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(f); string(got) != "A=1\nB=2\n" {
		t.Fatalf("got %q", got)
	}
	if err := ci.ExportEnv(f, "C", "x\nD=y"); err == nil {
		t.Fatal("a newline in a value must be refused")
	}
	if err := ci.ExportEnv(filepath.Join(f, "no", "dir"), "A", "1"); err == nil {
		t.Fatal("unwritable file must error")
	}
}

func TestGitHubToken(t *testing.T) {
	var gotAuth, gotAudience string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAudience = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		if r.URL.Query().Get("keep") != "1" {
			http.Error(w, "lost the runner's own query", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"value":"the-token"}`))
	}))
	defer srv.Close()
	env := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "?keep=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bearer"}
	get := func(k string) string { return env[k] }

	tok, err := ci.GitHubToken(context.Background(), nil, get, "my aud")
	if err != nil || tok != "the-token" || gotAuth != "Bearer runner-bearer" || gotAudience != "my aud" {
		t.Fatalf("got %q %v auth=%q aud=%q", tok, err, gotAuth, gotAudience)
	}

	if _, err := ci.GitHubToken(context.Background(), nil, func(string) string { return "" }, "a"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("missing permission: %v", err)
	}
	env["ACTIONS_ID_TOKEN_REQUEST_URL"] = srv.URL
	if _, err := ci.GitHubToken(context.Background(), nil, get, "a"); err == nil {
		t.Fatal("runner error must surface")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer empty.Close()
	env["ACTIONS_ID_TOKEN_REQUEST_URL"] = empty.URL
	if _, err := ci.GitHubToken(context.Background(), nil, get, "a"); err == nil {
		t.Fatal("empty token must be refused")
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }
