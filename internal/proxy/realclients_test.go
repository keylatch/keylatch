package proxy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file drive the real git and gh binaries through the
// GitHub proxy the way docs/gateway-service.md tells a sandbox or VM guest to,
// against a local fake GitHub. They are skipped where git or gh is missing,
// unless KEYLATCH_REQUIRE_REAL_CLIENTS is set (the CI runner on Linux sets it).

const (
	acmeToken   = "ghs_ACMEinstallationTOKEN0001"
	globexToken = "ghs_GLOBEXinstallationTOKEN0002"
	realProxyTk = "proxy-caller-token-0003"
	placeholder = "ghp_PLACEHOLDERplaceholder0004"
)

func requireBinary(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("KEYLATCH_REQUIRE_REAL_CLIENTS") != "" {
			t.Fatalf("%s is required (KEYLATCH_REQUIRE_REAL_CLIENTS is set) but not installed: %v", name, err)
		}
		t.Skipf("%s is not installed", name)
	}
	return p
}

type cmdResult struct {
	stdout, stderr string
	err            error
}

func (c cmdResult) all() string { return c.stdout + c.stderr }

func run(t *testing.T, dir string, env []string, name string, args ...string) cmdResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	return cmdResult{so.String(), se.String(), err}
}

// countingRelay forwards TCP to target and counts the connections it accepts.
type countingRelay struct {
	ln    net.Listener
	conns atomic.Int64
}

func newCountingRelay(t *testing.T, target string) *countingRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &countingRelay{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.conns.Add(1)
			go func() {
				u, err := net.Dial("tcp", target)
				if err != nil {
					_ = c.Close()
					return
				}
				go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
				_, _ = io.Copy(c, u)
				_ = c.Close()
			}()
		}
	}()
	return r
}

type realEnv struct {
	t        *testing.T
	fake     *fakeGitHub
	audit    *captureAudit
	logs     *syncBuffer
	relay    *countingRelay
	caPath   string
	home     string
	gitEnv   []string
	proxyURL func(user string) string
	git      string
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().String()
}

func newRealEnv(t *testing.T) *realEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake GitHub runs git http-backend as a CGI program; not exercised on Windows")
	}
	gitBin := requireBinary(t, "git")
	dir := t.TempDir()
	e := &realEnv{t: t, git: gitBin, audit: &captureAudit{}, logs: &syncBuffer{}, home: filepath.Join(dir, "home")}
	require.NoError(t, os.MkdirAll(e.home, 0o700))

	// Bare repositories: acme/widgets (seeded), acme/tools, acme/secret (not
	// on the allowlist), globex/gadgets.
	root := filepath.Join(dir, "remote")
	baseEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(dir, "seed.gitconfig"),
		"GIT_AUTHOR_NAME=Seed", "GIT_AUTHOR_EMAIL=seed@example.test", "GIT_COMMITTER_NAME=Seed", "GIT_COMMITTER_EMAIL=seed@example.test"}
	for _, r := range []string{"acme/widgets", "acme/tools", "acme/secret", "globex/gadgets"} {
		bare := filepath.Join(root, r+".git")
		require.NoError(t, os.MkdirAll(bare, 0o700))
		res := run(t, bare, baseEnv, gitBin, "init", "--bare", "-q", "-b", "main")
		require.NoError(t, res.err, res.all())
		work := filepath.Join(dir, "seed", strings.ReplaceAll(r, "/", "-"))
		require.NoError(t, os.MkdirAll(work, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(work, "README.md"), []byte("# "+r+"\n"), 0o600))
		for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"commit", "-q", "-m", "seed"}, {"push", "-q", bare, "main"}} {
			res := run(t, work, baseEnv, gitBin, args...)
			require.NoError(t, res.err, res.all())
		}
	}

	e.fake = newFakeGitHub(t, root, map[string]string{"acme": acmeToken, "globex": globexToken})

	// The proxy: one listener, two installations, fake App minting, a real
	// name-constrained CA, the real Serve loop and its timeouts.
	mint := func(tok string) proxy.TokenMinter {
		return func(context.Context) (string, time.Time, error) { return tok, time.Now().Add(time.Hour), nil }
	}
	acme, err := proxy.NewGitHubInjector("", []string{"acme/widgets", "acme/tools"}, mint(acmeToken))
	require.NoError(t, err)
	globex, err := proxy.NewGitHubInjector("", []string{"globex/gadgets"}, mint(globexToken))
	require.NoError(t, err)
	set, err := proxy.NewGitHubSet(acme, globex)
	require.NoError(t, err)
	permitted, err := proxy.PermittedDNS(acme.Hosts())
	require.NoError(t, err)
	e.caPath = filepath.Join(dir, "ca.pem")
	ca, err := proxy.LoadOrCreateFileCA(e.caPath, filepath.Join(dir, "ca.key"), permitted)
	require.NoError(t, err)
	addr := freeAddr(t)
	srv := &proxy.Server{
		Addr: addr, Profile: proxy.ProxyProfile{Hosts: acme.Hosts()}, CA: ca, GitHub: set,
		Token: realProxyTk, AuditEmitter: e.audit, UpstreamTransport: e.fake.transport(),
	}
	log.SetOutput(e.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	e.relay = newCountingRelay(t, addr)
	e.proxyURL = func(user string) string {
		return fmt.Sprintf("http://%s:%s@%s", user, realProxyTk, e.relay.ln.Addr())
	}

	// The guest settings of docs/gateway-service.md, written the documented way.
	gitconfig := filepath.Join(dir, "guest.gitconfig")
	e.gitEnv = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + gitconfig,
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "LC_ALL=C"}
	for _, kv := range [][2]string{
		{"http.sslCAInfo", e.caPath},
		{"http.https://github.com/acme/.proxy", e.proxyURL("acme")},
		{"http.https://github.com/globex/.proxy", e.proxyURL("globex")},
		{"credential.helper", ""},
		{"user.name", "Sandbox"}, {"user.email", "sandbox@example.test"}, {"init.defaultBranch", "main"},
	} {
		res := run(t, dir, e.gitEnv, gitBin, "config", "--global", kv[0], kv[1])
		require.NoError(t, res.err, res.all())
	}
	return e
}

func (e *realEnv) gitRun(dir string, extraEnv []string, args ...string) cmdResult {
	e.t.Helper()
	return run(e.t, dir, append(append([]string(nil), e.gitEnv...), extraEnv...), e.git, args...)
}

func (e *realEnv) upstreamFor(pathPrefix string) []recordedRequest {
	var out []recordedRequest
	for _, r := range e.fake.requests() {
		if strings.HasPrefix(r.Path, pathPrefix) {
			out = append(out, r)
		}
	}
	return out
}

// noSecretsIn fails when the real installation or proxy tokens appear in text.
func noSecretsIn(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{acmeToken, globexToken, realProxyTk} {
		assert.NotContains(t, text, s, what)
	}
}

func TestRealGitAndGhThroughProxy(t *testing.T) {
	e := newRealEnv(t)
	work := t.TempDir()
	clone := filepath.Join(work, "widgets")
	var outputs []string

	t.Run("clone_commit_push_new_branch", func(t *testing.T) {
		before := e.relay.conns.Load()
		res := e.gitRun(work, nil, "clone", "https://github.com/acme/widgets.git", clone)
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		assert.FileExists(t, filepath.Join(clone, "README.md"))
		// curl first asks without credentials and gets 407 (one connection);
		// info/refs and upload-pack then share one CONNECT tunnel (keep-alive).
		assert.LessOrEqual(t, e.relay.conns.Load()-before, int64(2), "the clone's requests share a tunnel")
		assert.GreaterOrEqual(t, len(e.upstreamFor("/acme/widgets.git")), 2)

		require.NoError(t, os.WriteFile(filepath.Join(clone, "feature.txt"), []byte("hello\n"), 0o600))
		for _, args := range [][]string{{"checkout", "-q", "-b", "feature"}, {"add", "."}, {"commit", "-q", "-m", "add feature"}} {
			res := e.gitRun(clone, nil, args...)
			require.NoError(t, res.err, res.all())
		}
		res = e.gitRun(clone, nil, "push", "origin", "feature")
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		out := run(t, filepath.Join(e.fake.root, "acme", "widgets.git"), e.gitEnv, e.git, "branch", "--list", "feature")
		assert.Contains(t, out.stdout, "feature", "the push landed in the bare repository")
	})

	t.Run("push_over_one_mebibyte_streams", func(t *testing.T) {
		blob := make([]byte, 3<<20)
		_, _ = rand.Read(blob)
		require.NoError(t, os.WriteFile(filepath.Join(clone, "blob.bin"), blob, 0o600))
		for _, args := range [][]string{{"add", "."}, {"commit", "-q", "-m", "add a 3 MiB blob"}} {
			res := e.gitRun(clone, nil, args...)
			require.NoError(t, res.err, res.all())
		}
		res := e.gitRun(clone, nil, "push", "origin", "feature")
		require.NoError(t, res.err, res.all())
		var big *recordedRequest
		for _, r := range e.upstreamFor("/acme/widgets.git/git-receive-pack") {
			if len(r.Header) > 0 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-git-receive-pack-request") {
				r := r
				big = &r
			}
		}
		require.NotNil(t, big)
		assert.Equal(t, 200, big.Status)
	})

	t.Run("gh_api_user_pr_create_and_view", func(t *testing.T) {
		ghBin := requireBinary(t, "gh")
		cfg := filepath.Join(work, "gh-config")
		require.NoError(t, os.MkdirAll(cfg, 0o700))
		ghEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.home, "GH_CONFIG_DIR=" + cfg,
			"GH_TOKEN=" + placeholder, "GH_HOST=github.com", "HTTPS_PROXY=" + e.proxyURL("acme"), "SSL_CERT_FILE=" + e.caPath,
			"GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1", "NO_COLOR=1", "GH_NO_EXTENSION_UPDATE_NOTIFIER=1",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(work, "guest.gitconfig")}
		res := run(t, clone, ghEnv, ghBin, "api", "user")
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		assert.Contains(t, res.stdout, "keylatch-app")

		res = run(t, clone, ghEnv, ghBin, "pr", "create", "--draft", "--title", "Add feature", "--body", "from a sandbox", "--head", "feature", "--base", "main")
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		assert.Contains(t, res.stdout, "https://github.com/acme/widgets/pull/7")

		res = run(t, clone, ghEnv, ghBin, "pr", "view", "7", "--json", "number,title,isDraft")
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		assert.Contains(t, res.stdout, `"isDraft":true`)

		// The API calls carried the acme installation token, as a Bearer.
		for _, r := range e.fake.requests() {
			if r.Host != "github.com" && r.Path != "" {
				assert.Equal(t, "Bearer "+acmeToken, r.Header.Get("Authorization"), r.Method+" "+r.Host+r.Path)
			}
		}
	})

	t.Run("keep_alive_and_expect_continue", func(t *testing.T) {
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(mustRead(t, e.caPath)))
		pu, _ := url.Parse(e.proxyURL("acme"))
		tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, ExpectContinueTimeout: time.Second}
		defer tr.CloseIdleConnections()
		cl := &http.Client{Transport: tr}
		before := e.relay.conns.Load()
		for i := 0; i < 6; i++ {
			req, _ := http.NewRequest("POST", "https://api.github.com/graphql", strings.NewReader(`{"query":"{viewer{login}}"}`))
			req.Header.Set("Expect", "100-continue")
			req.Header.Set("Authorization", "Bearer "+placeholder)
			resp, err := cl.Do(req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assert.Equal(t, 200, resp.StatusCode)
		}
		assert.Equal(t, int64(1), e.relay.conns.Load()-before, "six requests, one tunnel")
	})

	t.Run("refusals", func(t *testing.T) {
		before := len(e.fake.requests())
		// A repository of the owner that is not on the list.
		res := e.gitRun(work, nil, "clone", "https://github.com/acme/secret.git", filepath.Join(work, "secret"))
		outputs = append(outputs, res.all())
		require.Error(t, res.err)
		assert.Contains(t, res.stderr, "403")
		// The proxy user selects acme but the path is globex's.
		res = e.gitRun(work, nil, "-c", "http.https://github.com/globex/.proxy="+e.proxyURL("acme"), "clone", "https://github.com/globex/gadgets.git", filepath.Join(work, "gadgets"))
		outputs = append(outputs, res.all())
		require.Error(t, res.err)
		assert.Contains(t, res.stderr, "403")
		// A proxy user that is no configured owner: the tunnel is refused.
		res = e.gitRun(work, nil, "-c", "http.https://github.com/acme/.proxy="+e.proxyURL("nobody"), "clone", "https://github.com/acme/widgets.git", filepath.Join(work, "nobody"))
		outputs = append(outputs, res.all())
		require.Error(t, res.err)
		assert.Contains(t, res.stderr, "407")
		// A wrong proxy password is refused too.
		bad := strings.Replace(e.proxyURL("acme"), realProxyTk, "wrong", 1)
		res = e.gitRun(work, nil, "-c", "http.https://github.com/acme/.proxy="+bad, "clone", "https://github.com/acme/widgets.git", filepath.Join(work, "badpw"))
		outputs = append(outputs, res.all())
		require.Error(t, res.err)
		assert.Equal(t, before, len(e.fake.requests()), "refused requests never reach upstream")
	})

	t.Run("placeholder_credentials_are_replaced", func(t *testing.T) {
		url := "https://x-access-token:" + placeholder + "@github.com/acme/tools.git"
		// proactiveAuth sends the placeholder on the first request, so the
		// proxy has something to strip.
		res := e.gitRun(work, []string{"GIT_TRACE_CURL=1", "GIT_TRACE_REDACT=0"}, "-c", "http.proactiveAuth=basic", "clone", url, filepath.Join(work, "tools"))
		require.NoError(t, res.err, res.all())
		sent := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + placeholder))
		assert.Contains(t, res.stderr, sent, "git really sent the placeholder to the proxy")
	})

	t.Run("two_installations_use_their_own_token", func(t *testing.T) {
		res := e.gitRun(work, nil, "clone", "https://github.com/globex/gadgets.git", filepath.Join(work, "gadgets"))
		outputs = append(outputs, res.all())
		require.NoError(t, res.err, res.all())
		for _, r := range e.upstreamFor("/globex/gadgets.git") {
			assert.Contains(t, r.Header.Get("Authorization"), "Basic ")
			assert.Equal(t, 200, r.Status)
		}
	})

	t.Run("nothing_leaks", func(t *testing.T) {
		for _, r := range e.fake.requests() {
			dump := fmt.Sprint(r.Header)
			assert.NotContains(t, dump, placeholder, "upstream saw the placeholder: %s %s", r.Method, r.Path)
			assert.NotContains(t, dump, realProxyTk, "upstream saw the proxy token")
			assert.Empty(t, r.Header.Get("Proxy-Authorization"))
			// The base64 of the proxy credentials never reaches upstream either.
			assert.NotContains(t, r.Header.Get("Authorization"), "placeholder")
		}
		noSecretsIn(t, "proxy log", e.logs.String())
		for _, ev := range e.audit.events {
			noSecretsIn(t, "audit event", fmt.Sprintf("%+v", ev))
		}
		for _, o := range outputs {
			noSecretsIn(t, "git or gh output", strings.ReplaceAll(o, realProxyTk, ""))
		}
		assert.NotEmpty(t, e.audit.events, "refusals are audited")
	})
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}
