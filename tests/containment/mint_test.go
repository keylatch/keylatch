//go:build containment && linux

package containment

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const mintedPrefix = "ghs_mintedTestToken"

type mintEnv struct {
	*sandboxEnv
	work, bare string
	auditFile  string
	apiLog     string

	mu   sync.Mutex
	auth []string
}

func (e *mintEnv) seen() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.auth...)
}

func gitOnHost(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func setupMint(t *testing.T) *mintEnv {
	t.Helper()
	requireBwrap(t)
	for _, tool := range []string{"git", "gh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	backend := "/usr/libexec/git-core/git-http-backend"
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is not installed")
	}
	root, err := os.MkdirTemp("/tmp", "klm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	e := &mintEnv{sandboxEnv: &sandboxEnv{
		root: root, bin: filepath.Join(root, "bin"), runtimeDir: filepath.Join(root, "run"), state: filepath.Join(root, "state"),
	}}
	e.work = filepath.Join(root, "work")
	e.bare = filepath.Join(root, "remote", "patrikmichi", "app.git")
	for _, d := range []string{e.bin, e.runtimeDir, e.state, filepath.Join(root, "home"), e.work, e.bare} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gitOnHost(t, e.bare, "init", "--bare", "-q")
	gitOnHost(t, e.work, "init", "-q")
	if err := os.WriteFile(filepath.Join(e.work, "f.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOnHost(t, e.work, "add", "f.txt")
	gitOnHost(t, e.work, "commit", "-q", "-m", "init")

	build(t, e.bin+"/", "../../cmd/keylatch")
	build(t, filepath.Join(e.bin, "mintd"), "./testdata/mintd")

	cert, certPEM := fakeProviderCert(t)
	caFile := filepath.Join(root, "upstream.pem")
	if err := os.WriteFile(caFile, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	git := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + filepath.Join(root, "remote"), "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=minted"}}
	provider := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		e.mu.Lock()
		e.auth = append(e.auth, r.Host+" "+h)
		e.mu.Unlock()
		token := h
		if raw, ok := strings.CutPrefix(h, "Basic "); ok {
			dec, _ := base64.StdEncoding.DecodeString(raw)
			_, token, _ = strings.Cut(string(dec), ":")
		}
		if !strings.Contains(token, mintedPrefix) {
			w.Header().Set("WWW-Authenticate", `Basic realm="github"`)
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Host == "github.com":
			git.ServeHTTP(w, r)
		case r.URL.Path == "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"login":"octo"}`)
		case r.URL.Path == "/repos/patrikmichi/app/pulls" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"number":7,"html_url":"https://github.com/patrikmichi/app/pull/7"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	provider.EnableHTTP2 = true
	provider.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	provider.StartTLS()
	t.Cleanup(provider.Close)

	e.auditFile = filepath.Join(root, "audit.jsonl")
	e.apiLog = filepath.Join(root, "api.log")
	daemon := exec.Command(filepath.Join(e.bin, "mintd"),
		"--upstream", provider.Listener.Addr().String(), "--upstream-ca", caFile, "--audit", e.auditFile, "--api-log", e.apiLog)
	daemon.Env = cleanEnv("HOME="+filepath.Join(root, "home"), "XDG_RUNTIME_DIR="+e.runtimeDir, "KEYLATCH_CONFIG_DIR="+e.state)
	var daemonLog bytes.Buffer
	daemon.Stdout, daemon.Stderr = &daemonLog, &daemonLog
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
	})
	socket := filepath.Join(e.runtimeDir, "keylatch", "keylatchd.sock")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if c, err := net.Dial("unix", socket); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not start: %s", daemonLog.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return e
}

// sandboxed runs keylatchArgs through the thin client inside a sandbox with no
// network and only the control socket, as an agent harness would.
func (e *mintEnv) sandboxed(t *testing.T, env map[string]string, keylatchArgs ...string) (string, string, int) {
	t.Helper()
	args := []string{
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/tmp/home",
		"--unshare-pid", "--unshare-net", "--unshare-ipc", "--die-with-parent", "--clearenv",
		"--ro-bind", e.bin, e.bin, "--bind", e.runtimeDir, e.runtimeDir, "--bind", e.work, e.work,
		"--setenv", "PATH", e.bin + ":/usr/bin:/bin",
		"--setenv", "HOME", "/tmp/home", "--setenv", "XDG_RUNTIME_DIR", e.runtimeDir,
		"--setenv", "GH_PROMPT_DISABLED", "1", "--setenv", "GH_NO_UPDATE_NOTIFIER", "1",
	}
	for k, v := range env {
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--", "keylatch")
	cmd := exec.Command("bwrap", append(args, keylatchArgs...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	code := 0
	var exitErr *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func (e *mintEnv) runApp(t *testing.T, env map[string]string, script string) (string, string, int) {
	t.Helper()
	return e.sandboxed(t, env, "run", "--tier", "D3", "--repo", "patrikmichi/app",
		"--permission", "contents=write", "--permission", "pull_requests=write", "github-app", "--", "sh", "-c", script)
}

func (e *mintEnv) leaks(t *testing.T, streams ...string) {
	t.Helper()
	for _, s := range streams {
		if strings.Contains(s, mintedPrefix) {
			t.Errorf("a minted token leaked into %q", s)
		}
	}
	raw, _ := os.ReadFile(e.auditFile)
	if bytes.Contains(raw, []byte(mintedPrefix)) {
		t.Error("the audit log holds a minted token")
	}
}

func TestMintedTokenThroughPlaceholder(t *testing.T) {
	for name, env := range map[string]map[string]string{"agent": {"CLAUDECODE": "1"}, "host": nil} {
		t.Run(name, func(t *testing.T) {
			e := setupMint(t)
			script := `env | grep -E '^(GH_TOKEN|GITHUB_TOKEN)=';
gh api user --jq .login || exit 1
gh api -X POST repos/patrikmichi/app/pulls -f title=t -f head=feature -f base=main --jq .html_url || exit 1
git -C ` + e.work + ` remote add origin https://github.com/patrikmichi/app.git
git -C ` + e.work + ` push origin HEAD:refs/heads/feature || exit 1
printf 'protocol=https\nhost=github.com\n\n' | git credential fill`
			out, errOut, code := e.runApp(t, env, script)
			t.Logf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
			if code != 0 {
				t.Fatal("the run failed")
			}
			e.leaks(t, out, errOut)
			for _, want := range []string{"GH_TOKEN=ghs_klph_", "GITHUB_TOKEN=ghs_klph_", "octo", "https://github.com/patrikmichi/app/pull/7", "username=x-access-token", "password=ghs_klph_"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q", want)
				}
			}
			if err := exec.Command("git", "-C", e.bare, "rev-parse", "--verify", "refs/heads/feature").Run(); err != nil {
				t.Errorf("git push did not reach the remote: %v", err)
			}
			var api, gitAuth bool
			for _, a := range e.seen() {
				switch {
				case strings.HasPrefix(a, "api.github.com ") && strings.Contains(a, mintedPrefix):
					api = true
				case strings.HasPrefix(a, "github.com Basic "):
					gitAuth = true
				}
				if strings.Contains(a, "klph_") {
					t.Errorf("a placeholder reached the provider: %q", a)
				}
			}
			if !api || !gitAuth {
				t.Errorf("provider saw api=%v git=%v: %q", api, gitAuth, e.seen())
			}
			time.Sleep(300 * time.Millisecond)
			log, _ := os.ReadFile(e.apiLog)
			if !strings.Contains(string(log), "mint 1 [app]") || !strings.Contains(string(log), "revoke "+mintedPrefix) {
				t.Errorf("expected one mint and a revocation when the run ended: %q", log)
			}
		})
	}
}

func TestMintToStdoutRefusedInsideSandbox(t *testing.T) {
	e := setupMint(t)
	for name, env := range map[string]map[string]string{"agent": {"CLAUDECODE": "1"}, "host": nil} {
		out, errOut, code := e.sandboxed(t, env, "mint", "github-app", "--repo", "patrikmichi/app", "--permission", "contents=write", "--format", "json")
		if code != 2 || out != "" {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, errOut)
		}
		e.leaks(t, out, errOut)
	}
}

func TestMintedRunOutsidePolicyIsRefused(t *testing.T) {
	e := setupMint(t)
	for _, args := range [][]string{
		{"--repo", "other/app", "--permission", "contents=write"},
		{"--repo", "patrikmichi/app", "--permission", "contents=admin"},
		{"--repo", "patrikmichi/app", "--permission", "administration=write"},
	} {
		out, errOut, code := e.sandboxed(t, map[string]string{"CLAUDECODE": "1"},
			append(append([]string{"run", "--tier", "D3"}, args...), "github-app", "--", "true")...)
		if code == 0 || !strings.Contains(errOut, "denied by policy") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errOut)
		}
	}
	if log, _ := os.ReadFile(e.apiLog); len(log) != 0 {
		t.Errorf("a refused run reached the App API: %q", log)
	}
}
