package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

func ccSkipWithoutPermBits(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permission bits are not enforced here")
	}
}

// ccStoreFile points the given *_PATH override at a fresh file location.
func ccStoreFile(t *testing.T, envKey string) string {
	t.Helper()
	ccEnv(t)
	p := filepath.Join(t.TempDir(), "store.json")
	t.Setenv(envKey, p)
	return p
}

func TestCCLocalStores_CorruptFileFailsEveryCommand(t *testing.T) {
	cases := []struct {
		env  string
		args [][]string
	}{
		{"KEYLATCH_PROJECTS_PATH", [][]string{
			{"projects", "list"},
			{"projects", "create", "p1"},
			{"projects", "delete", "p1"},
		}},
		{"KEYLATCH_SESSIONS_PATH", [][]string{
			{"sessions", "list"},
			{"sessions", "start", "--actor", "a"},
			{"sessions", "kill", "s1"},
		}},
		{"KEYLATCH_RECEIPTS_PATH", [][]string{
			{"receipts", "list"},
			{"receipts", "show", "acc"},
			{"receipts", "tail"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			p := ccStoreFile(t, tc.env)
			if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, args := range tc.args {
				_, _, err := ccRun(t, "", args...)
				var syn *json.SyntaxError
				if err == nil || !errors.As(err, &syn) {
					t.Errorf("%v: err = %v, want JSON syntax error", args, err)
				}
			}
			if b, _ := os.ReadFile(p); string(b) != "{not json" {
				t.Fatalf("corrupt store was overwritten: %q", b)
			}
		})
	}
}

func TestCCLocalStores_UnreadablePathIsAnError(t *testing.T) {
	for _, env := range []string{"KEYLATCH_PROJECTS_PATH", "KEYLATCH_SESSIONS_PATH", "KEYLATCH_RECEIPTS_PATH"} {
		t.Run(env, func(t *testing.T) {
			p := ccStoreFile(t, env)
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch env {
			case "KEYLATCH_PROJECTS_PATH":
				_, err = loadProjects()
			case "KEYLATCH_SESSIONS_PATH":
				_, err = loadSessions()
			default:
				_, err = loadReceipts()
			}
			if err == nil {
				t.Fatal("reading a directory as the store must fail")
			}
		})
	}
}

func TestCCLocalStores_ReadOnlyFileRejectsWrites(t *testing.T) {
	ccSkipWithoutPermBits(t)
	cases := []struct {
		env  string
		seed string
		args [][]string
	}{
		{"KEYLATCH_PROJECTS_PATH", `[{"name":"keep","created_at":"2026-01-01T00:00:00Z"}]`, [][]string{
			{"projects", "create", "p2"},
			{"projects", "delete", "keep"},
		}},
		{"KEYLATCH_SESSIONS_PATH", `[{"id":"s1","actor":"a","active":true}]`, [][]string{
			{"sessions", "start", "--actor", "b"},
			{"sessions", "kill", "s1"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			p := ccStoreFile(t, tc.env)
			if err := os.WriteFile(p, []byte(tc.seed), 0o400); err != nil {
				t.Fatal(err)
			}
			for _, args := range tc.args {
				if _, _, err := ccRun(t, "", args...); err == nil || !os.IsPermission(err) {
					t.Errorf("%v: err = %v, want permission error", args, err)
				}
			}
			if b, _ := os.ReadFile(p); string(b) != tc.seed {
				t.Fatalf("read-only store changed: %q", b)
			}
		})
	}

	t.Run("receipts append", func(t *testing.T) {
		p := ccStoreFile(t, "KEYLATCH_RECEIPTS_PATH")
		if err := os.WriteFile(p, []byte("[]"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := AppendReceipt(runner.Receipt{Actor: "a"}); err == nil || !os.IsPermission(err) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCCLocalStores_ParentIsAFile(t *testing.T) {
	ccEnv(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	under := filepath.Join(blocker, "sub", "store.json")
	t.Setenv("KEYLATCH_PROJECTS_PATH", under)
	t.Setenv("KEYLATCH_SESSIONS_PATH", under)
	t.Setenv("KEYLATCH_RECEIPTS_PATH", under)

	if err := saveProjects(nil); err == nil {
		t.Error("saveProjects under a file must fail")
	}
	if err := saveSessions(nil); err == nil {
		t.Error("saveSessions under a file must fail")
	}
	if err := AppendReceipt(runner.Receipt{Actor: "a"}); err == nil {
		t.Error("AppendReceipt under a file must fail")
	}
}

func TestCCReceiptsAppend_CorruptExistingFile(t *testing.T) {
	p := ccStoreFile(t, "KEYLATCH_RECEIPTS_PATH")
	if err := os.WriteFile(p, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendReceipt(runner.Receipt{Actor: "a"}); err == nil {
		t.Fatal("append onto a corrupt receipts file must fail instead of discarding history")
	}
	if b, _ := os.ReadFile(p); string(b) != "nope" {
		t.Fatalf("corrupt file overwritten: %q", b)
	}
}

func TestCCProjectsDelete_KeepsOthers(t *testing.T) {
	p := ccStoreFile(t, "KEYLATCH_PROJECTS_PATH")
	for _, n := range []string{"alpha", "beta", "gamma"} {
		if _, _, err := ccRun(t, "", "projects", "create", n); err != nil {
			t.Fatalf("create %s: %v", n, err)
		}
	}
	out, _, err := ccRun(t, "", "projects", "delete", "beta")
	if err != nil || out != "project \"beta\" deleted\n" {
		t.Fatalf("delete: %q, %v", out, err)
	}
	var left []projectEntry
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &left); err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 || left[0].Name != "alpha" || left[1].Name != "gamma" {
		t.Fatalf("remaining = %+v", left)
	}
}

func TestCCReceiptsList_Table(t *testing.T) {
	ccStoreFile(t, "KEYLATCH_RECEIPTS_PATH")
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for i, actor := range []string{"first", "second", "third"} {
		if err := AppendReceipt(runner.Receipt{Timestamp: ts, Actor: actor, Connection: "openai", Capability: "models", PolicyDecision: "allow", ExitCode: i}); err != nil {
			t.Fatal(err)
		}
	}
	out, _, err := ccRun(t, "", "receipts", "list", "--limit", "2")
	if err != nil {
		t.Fatalf("receipts list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "TIMESTAMP") {
		t.Fatalf("table = %q", out)
	}
	if strings.Contains(out, "first") || !strings.Contains(lines[1], "second") || !strings.Contains(lines[2], "third") {
		t.Fatalf("--limit must keep the newest receipts: %q", out)
	}
	if !strings.Contains(lines[2], "2026-03-04T05:06:07Z") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "2") {
		t.Fatalf("row = %q", lines[2])
	}
}

func TestCCReceiptsTailFollow_Errors(t *testing.T) {
	ccEnv(t)
	refused := ccClosedAddr(t)
	cases := []struct {
		name string
		addr string
		srv  bool
		want string
	}{
		{"malformed addr", "no-port", false, "KEYLATCH_UI_ADDR"},
		{"bad host", "bad host:80", false, "receipts tail:"},
		{"refused", refused, false, "Is keylatchd running?"},
		{"non-200", "", true, "server returned 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr
			if tc.srv {
				addr = ccStatusServer(t, 503)
			}
			t.Setenv("KEYLATCH_UI_ADDR", addr)
			_, _, err := ccRun(t, "", "receipts", "tail", "--follow")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCCScaffold_RejectsBadInput(t *testing.T) {
	ccEnv(t)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "out", "taken.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"category", []string{"acme", "--category", "Bad Cat", "--out-dir", dir}, `category "Bad Cat" is invalid`},
		{"field without env", []string{"acme", "--category", "ai", "--field", "api_key", "--out-dir", dir}, "expected format name:ENV_VAR"},
		{"field empty name", []string{"acme", "--category", "ai", "--field", " :ACME_KEY", "--out-dir", dir}, "must not be empty"},
		{"out dir under file", []string{"acme", "--category", "ai", "--out-dir", filepath.Join(blocker, "x")}, "scaffold: create dir"},
		{"output is a directory", []string{"taken", "--category", "ai", "--out-dir", filepath.Join(dir, "out")}, "scaffold: create"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ccRun(t, "", append([]string{"registry", "scaffold"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("rejected scaffolds wrote files: %v", entries)
	}
}

func TestCCRegistry_JSONOutputs(t *testing.T) {
	ccEnv(t)
	out, _, err := ccRun(t, "", "registry", "list", "--json")
	if err != nil {
		t.Fatalf("registry list --json: %v", err)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) == 0 {
		t.Fatalf("list json: %v (%d entries)", err, len(list))
	}
	found := false
	for _, e := range list {
		if e["provider"] == "openai" {
			found = true
		}
	}
	if !found {
		t.Fatal("openai missing from registry list --json")
	}

	out, _, err = ccRun(t, "", "registry", "describe", "openai", "--json")
	if err != nil {
		t.Fatalf("registry describe --json: %v", err)
	}
	var one map[string]any
	if err := json.Unmarshal([]byte(out), &one); err != nil || one["provider"] != "openai" || one["category"] != "ai" {
		t.Fatalf("describe json = %v (%v)", one, err)
	}
}

func TestCCRegistryReload_IgnoresLocalTemplates(t *testing.T) {
	cfgDir := ccEnv(t)
	ccWriteTemplate(t, cfgDir, "ccbroken", "provider: ccbroken\n")

	cmd := newRegistryReloadCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("reload with a local template present: %v", err)
	}
	if !strings.HasPrefix(out.String(), "registry: loaded ") {
		t.Fatalf("out = %q", out.String())
	}
	if _, err := registry.Get("ccbroken"); err == nil {
		t.Fatal("a local template must not be loaded")
	}
}

// ccClosedAddr returns a loopback host:port with nothing listening on it.
func ccClosedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// ccStatusServer serves every request with status and returns its host:port.
func ccStatusServer(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}
