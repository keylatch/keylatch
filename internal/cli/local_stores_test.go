package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

func ccSkipWithoutPermBits(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permission bits are not enforced here")
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
