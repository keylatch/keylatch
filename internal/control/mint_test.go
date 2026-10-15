//go:build !windows

package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/mintsession/mintsessiontest"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/runner"
)

type unusedResolver struct{ t *testing.T }

func (r unusedResolver) Resolve(_ context.Context, connection, field string) ([]byte, error) {
	r.t.Errorf("the stored credential store was asked for %s.%s", connection, field)
	return nil, fmt.Errorf("unexpected read")
}

type githubFixture struct {
	env   map[string]string
	api   *mintsessiontest.Stub
	store *mintsessiontest.Store
	audit *recordingAudit
	mu    sync.Mutex
	seen  []string
}

func (g *githubFixture) authSeen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

func (g *githubFixture) auditJSON() string {
	g.audit.mu.Lock()
	defer g.audit.mu.Unlock()
	b, _ := json.Marshal(g.audit.events)
	return string(b)
}

func startGitHubDaemon(t *testing.T, p *config.GitHubAppMintPolicy) *githubFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"api.github.com", "uploads.github.com", "github.com"}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "github"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	g := &githubFixture{audit: &recordingAudit{}}
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.seen = append(g.seen, r.Host+" "+r.Header.Get("Authorization"))
		g.mu.Unlock()
		_, _ = io.WriteString(w, `{"login":"octo"}`)
	}))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	up.StartTLS()
	t.Cleanup(up.Close)

	g.api = mintsessiontest.NewStub()
	t.Cleanup(g.api.Close)
	g.store, err = mintsessiontest.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	if p != nil {
		cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: p}}}
	}
	minter := mintsession.New(mintsession.Config{
		Store: g.store, APIBase: g.api.URL, Audit: g.audit, Policy: func() (config.Config, error) { return cfg, nil },
	})

	mgr, err := placeholder.NewManager(placeholder.Config{
		Resolver: unusedResolver{t}, Audit: g.audit,
		Upstream: placeholder.Upstream{Roots: pool, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, up.Listener.Addr().String())
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)

	dir, err := os.MkdirTemp("/tmp", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	g.env = map[string]string{"KEYLATCH_CONFIG_DIR": dir + "/state", "KEYLATCH_SOCKET": dir + "/s/k.sock"}
	startServer(t, g.env, Config{
		Env: lookupOf(g.env), Binary: "/bin/true", Placeholders: mgr,
		Mint: func(ctx context.Context, kind Kind, rr *RunRequest) (placeholder.Credential, error) {
			cred, err := minter.Open(ctx, mintsession.Request{
				Connection: rr.Connection, Repository: rr.Repository, Permissions: rr.Permissions, Caller: mint.CallerKind(kind),
			})
			if err != nil {
				return nil, err
			}
			return cred, nil
		},
	})
	return g
}

// connect returns a client whose signals reflect the environment as it is now.
func (g *githubFixture) connect(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(lookupOf(g.env))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func agentPolicy() *config.GitHubAppMintPolicy {
	return &config.GitHubAppMintPolicy{
		PlaceholderCallers: []string{"agent"},
		AllowOwners:        []string{mintsessiontest.Owner},
		PermissionCeiling:  map[string]string{"contents": "write", "pull_requests": "write"},
	}
}

// TestGitHubChild is the process `run` starts below: a tool that reads its
// token from the environment and calls GitHub the way gh and git do.
func TestGitHubChild(t *testing.T) {
	if os.Getenv("HELPER_GH_CHILD") != "1" {
		return
	}
	fmt.Printf("GH_TOKEN=%s\nGITHUB_TOKEN=%s\n", os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	fmt.Printf("git=%s:%s:%s:%s\n", os.Getenv("GIT_CONFIG_COUNT"), os.Getenv("GIT_CONFIG_KEY_0"), os.Getenv("GIT_CONFIG_KEY_1"), os.Getenv("GIT_TERMINAL_PROMPT"))
	fmt.Printf("helper=%s session=%t socket=%t\n", os.Getenv("GIT_CONFIG_VALUE_1"), os.Getenv(runner.ProxySessionVar) != "", os.Getenv("KEYLATCH_SOCKET") != "")
	for _, c := range []struct{ url, scheme string }{
		{"https://api.github.com/user", "token"},
		{"https://uploads.github.com/repos/x", "Bearer"},
	} {
		req, _ := http.NewRequest("GET", c.url, nil)
		req.Header.Set("Authorization", c.scheme+" "+os.Getenv("GH_TOKEN"))
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			fmt.Printf("request: %v\n", err)
			os.Exit(3)
		}
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("status=%d body=%s\n", resp.StatusCode, body)
	}
	os.Exit(0)
}

func runGitHubChild(t *testing.T, g *githubFixture, extra ...string) (string, string, int) {
	t.Helper()
	t.Setenv("HELPER_GH_CHILD", "1")
	t.Setenv("GH_TOKEN", "ambient-token-must-be-replaced")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	args := append([]string{"run", "github-app", "--repo", mintsessiontest.Owner + "/app"}, extra...)
	args = append(args, "--", os.Args[0], "-test.run=^TestGitHubChild$")
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(g.env), args, IO{Out: &out, ErrOut: &errOut})
	if !handled {
		t.Fatal("the daemon did not handle the run")
	}
	return out.String(), errOut.String(), code
}

func TestMintedRunHoldsOnlyPlaceholders(t *testing.T) {
	g := startGitHubDaemon(t, agentPolicy())
	g.env["CLAUDECODE"] = "1"
	out, errOut, code := runGitHubChild(t, g, "--permission", "contents=write")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	real := mintsessiontest.Token(1)
	for name, text := range map[string]string{"stdout": out, "stderr": errOut, "audit": g.auditJSON()} {
		if strings.Contains(text, real) {
			t.Errorf("the minted token appears in the %s", name)
		}
	}
	for _, want := range []string{
		"GH_TOKEN=ghs_klph_", "GITHUB_TOKEN=ghs_klph_",
		"git=2:credential.helper:credential.https://github.com.helper:0",
		"session=true socket=true", "status=200 body={\"login\":\"octo\"}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("child output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ambient-token") {
		t.Error("the caller's own token reached the child")
	}

	seen := g.authSeen()
	if len(seen) != 2 || seen[0] != "api.github.com token "+real || seen[1] != "uploads.github.com Bearer "+real {
		t.Errorf("upstream saw %q", seen)
	}
	mints := g.api.Mints()
	if len(mints) != 1 || fmt.Sprint(mints[0]["repositories"]) != "[app]" || fmt.Sprint(mints[0]["permissions"]) != "map[contents:write]" {
		t.Errorf("mint requests %v", mints)
	}
	if got := g.api.Revoked(); len(got) != 1 || got[0] != real {
		t.Errorf("revoked %v, want the session's token revoked when the run ends", got)
	}
	if !strings.Contains(g.auditJSON(), `"caller_kind":"agent"`) {
		t.Errorf("no mint audit event for the agent: %s", g.auditJSON())
	}
}

func TestMintedRunIsRefusedByPolicy(t *testing.T) {
	cases := map[string]struct {
		policy *config.GitHubAppMintPolicy
		agent  bool
		args   []string
		code   string
	}{
		"no policy": {nil, true, []string{"--repo", "patrikmichi/app", "--permission", "contents=write"}, CodeRefused},
		"agent not listed": {func() *config.GitHubAppMintPolicy {
			p := agentPolicy()
			p.PlaceholderCallers = []string{"human"}
			return p
		}(), true, []string{"--repo", "patrikmichi/app", "--permission", "contents=write"}, CodeRefused},
		"agent listed only for minting to stdout": {func() *config.GitHubAppMintPolicy {
			p := agentPolicy()
			p.PlaceholderCallers = nil
			p.Callers = []string{"host"}
			return p
		}(), true, []string{"--repo", "patrikmichi/app", "--permission", "contents=write"}, CodeRefused},
		"repository outside the allowlist": {agentPolicy(), true, []string{"--repo", "other/app", "--permission", "contents=write"}, CodeRefused},
		"permission above the ceiling":     {agentPolicy(), true, []string{"--repo", "patrikmichi/app", "--permission", "contents=admin"}, CodeRefused},
		"no repository named":              {agentPolicy(), true, []string{"--permission", "contents=write"}, CodeBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := startGitHubDaemon(t, tc.policy)
			if tc.agent {
				g.env["CLAUDECODE"] = "1"
			}
			c := g.connect(t)
			rr := RunRequest{Connection: "github-app", Command: []string{"true"}}
			for i := 0; i < len(tc.args); i += 2 {
				if tc.args[i] == "--repo" {
					rr.Repository = tc.args[i+1]
				} else {
					rr.Permissions = append(rr.Permissions, tc.args[i+1])
				}
			}
			resp, err := c.RunSession(rr)
			if err != nil {
				t.Fatal(err)
			}
			if resp.OK || resp.Code != tc.code {
				t.Fatalf("got %+v, want refusal %s", resp, tc.code)
			}
			if len(g.api.Mints()) != 0 || g.store.Reads() != 0 {
				t.Errorf("a refused session minted %d tokens and read the store %d times", len(g.api.Mints()), g.store.Reads())
			}
		})
	}
}

func TestMintToStdoutStaysRefusedForAgents(t *testing.T) {
	g := startGitHubDaemon(t, agentPolicy())
	g.env["CLAUDECODE"] = "1"
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(g.env),
		[]string{"mint", "github-app", "--repo", "patrikmichi/app", "--permission", "contents=write", "--format", "json"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "not available to agent callers") {
		t.Fatalf("handled=%v code=%d stdout=%q stderr=%q", handled, code, out.String(), errOut.String())
	}
	if len(g.api.Mints()) != 0 {
		t.Error("a refused mint reached GitHub")
	}
}

func TestMintedTemplateCannotBeServedWithoutMinting(t *testing.T) {
	env, _, _ := startPlaceholderDaemon(t)
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := c.RunSession(RunRequest{Connection: "github-app", Repository: "patrikmichi/app", Command: []string{"true"}})
	if resp.OK || resp.Code != CodeUnavailable || !strings.Contains(resp.Error, "mints its credential") {
		t.Fatalf("got %+v", resp)
	}
}

func TestGitCredentialHelperReturnsOnlyThePlaceholder(t *testing.T) {
	g := startGitHubDaemon(t, agentPolicy())
	g.env["CLAUDECODE"] = "1"
	client := g.connect(t)
	resp, err := client.RunSession(RunRequest{Connection: "github-app", Repository: "patrikmichi/app", Permissions: []string{"contents=write"}, Command: []string{"git"}})
	if err != nil || !resp.OK {
		t.Fatalf("%+v %v", resp, err)
	}
	sess := resp.Session
	var ghToken string
	var helper string
	for _, a := range sess.Env.Set {
		switch a.Name {
		case "GH_TOKEN":
			ghToken = a.Value
		case "GIT_CONFIG_VALUE_1":
			helper = a.Value
		}
	}
	if !strings.HasPrefix(ghToken, "ghs_klph_") || helper != "!"+runner.BinaryPlaceholder+" git-credential" {
		t.Fatalf("session env: token %q helper %q", ghToken, helper)
	}

	ask := func(session, protocol, host string) *Credential {
		c, err := client.Credential(session, CredentialRequest{Protocol: protocol, Host: host})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := ask(sess.ProxyID, "https", "github.com")
	if c == nil || c.Username != "x-access-token" || c.Password != ghToken {
		t.Fatalf("helper answered %+v, want the session placeholder", c)
	}
	if c := ask(sess.ProxyID, "https", "GitHub.com:443"); c == nil {
		t.Error("the host match must ignore case and the default port")
	}
	for name, got := range map[string]*Credential{
		"another host":       ask(sess.ProxyID, "https", "evil.example"),
		"a subdomain":        ask(sess.ProxyID, "https", "gist.github.com"),
		"another port":       ask(sess.ProxyID, "https", "github.com:8443"),
		"plain http":         ask(sess.ProxyID, "http", "github.com"),
		"an unknown session": ask("nope", "https", "github.com"),
		"no session":         ask("", "https", "github.com"),
	} {
		if got != nil {
			t.Errorf("%s: helper answered %+v", name, got)
		}
	}
	if len(g.api.Mints()) != 0 {
		t.Error("answering the helper must not mint")
	}

	_ = client.EndSession(sess.ProxyID)
	if ask(sess.ProxyID, "https", "github.com") != nil {
		t.Error("an ended session still answers the helper")
	}
}

func TestGitCredentialVerbPrintsThePlaceholder(t *testing.T) {
	g := startGitHubDaemon(t, agentPolicy())
	g.env["CLAUDECODE"] = "1"
	client := g.connect(t)
	resp, _ := client.RunSession(RunRequest{Connection: "github-app", Repository: "patrikmichi/app", Permissions: []string{"contents=write"}, Command: []string{"git"}})
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	t.Cleanup(func() { _ = client.EndSession(resp.Session.ProxyID) })
	g.env[runner.ProxySessionVar] = resp.Session.ProxyID

	run := func(op, stdin string) (string, int) {
		var out bytes.Buffer
		code, handled := Handle(context.Background(), lookupOf(g.env), []string{"git-credential", op}, IO{In: strings.NewReader(stdin), Out: &out, ErrOut: io.Discard})
		if !handled {
			t.Fatal("git-credential must be answered by the thin client")
		}
		return out.String(), code
	}
	out, code := run("get", "protocol=https\nhost=github.com\npath=octo/app.git\n\n")
	if code != 0 || !strings.HasPrefix(out, "username=x-access-token\npassword=ghs_klph_") || strings.Contains(out, mintsessiontest.Token(1)) {
		t.Fatalf("get answered %q (exit %d)", out, code)
	}
	for _, tc := range []struct{ op, stdin string }{
		{"get", "protocol=https\nhost=evil.example\n\n"},
		{"get", "protocol=ssh\nhost=github.com\n\n"},
		{"store", "protocol=https\nhost=github.com\nusername=x\npassword=y\n\n"},
		{"erase", "protocol=https\nhost=github.com\n\n"},
	} {
		if out, code := run(tc.op, tc.stdin); out != "" || code != 0 {
			t.Errorf("%s %q answered %q (exit %d)", tc.op, tc.stdin, out, code)
		}
	}
	delete(g.env, runner.ProxySessionVar)
	if out, _ := run("get", "protocol=https\nhost=github.com\n\n"); out != "" {
		t.Errorf("a helper outside a session answered %q", out)
	}
}
