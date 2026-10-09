//go:build containment && linux

package containment

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const canary = "sk_test_CANARY9f3a7c1e5b2d4086a1c3e5f7092b4d6"

var providerHosts = []string{
	"api.stripe.com", "files.stripe.com", "api.github.com", "uploads.github.com", "github.com",
	"api.vercel.com", "api.openai.com", "api.anthropic.com", "evil.example",
}

type hit struct {
	Host, Method, Path, Query, Proto, Auth, APIKey string
	Header                                         http.Header
	Body                                           string
}

type placeholderEnv struct {
	*sandboxEnv
	canaryDir string
	auditFile string
	provider  *httptest.Server
	sinkAddr  string

	mu       sync.Mutex
	hits     []hit
	sinkHits int
}

func (e *placeholderEnv) providerHits() []hit {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]hit(nil), e.hits...)
}

func fakeProviderCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake providers"}, DNSNames: providerHosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func setupPlaceholder(t *testing.T) *placeholderEnv {
	t.Helper()
	requireBwrap(t)
	root, err := os.MkdirTemp("/tmp", "klp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	e := &placeholderEnv{sandboxEnv: &sandboxEnv{
		root: root, bin: filepath.Join(root, "bin"), runtimeDir: filepath.Join(root, "run"), state: filepath.Join(root, "state"),
	}}
	for _, d := range []string{e.bin, e.runtimeDir, e.state, filepath.Join(root, "home")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	build(t, e.bin+"/", "../../cmd/keylatch")
	build(t, filepath.Join(e.bin, "probe"), "./testdata/probe")
	build(t, filepath.Join(e.bin, "placeholderd"), "./testdata/placeholderd")

	cert, certPEM := fakeProviderCert(t)
	caFile := filepath.Join(root, "upstream.pem")
	if err := os.WriteFile(caFile, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	e.provider = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.hits = append(e.hits, hit{r.Host, r.Method, r.URL.Path, r.URL.RawQuery, r.Proto, r.Header.Get("Authorization"), r.Header.Get("x-api-key"), r.Header.Clone(), string(b)})
		e.mu.Unlock()
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "https://files.stripe.com/landing", http.StatusFound)
		case "/user", "/v2/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"login":"octo","id":1,"user":{"id":"u1","username":"octo","email":"o@example.com","name":"Octo"}}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true,"data":[]}`)
		}
	}))
	e.provider.EnableHTTP2 = true
	e.provider.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	e.provider.StartTLS()
	t.Cleanup(e.provider.Close)

	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	e.sinkAddr = sink.Addr().String()
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.sinkHits++
			e.mu.Unlock()
			_ = c.Close()
		}
	}()
	udp, err := net.ListenPacket("udp", e.sinkAddr)
	if err == nil {
		t.Cleanup(func() { _ = udp.Close() })
		go func() {
			buf := make([]byte, 512)
			for {
				if _, _, err := udp.ReadFrom(buf); err != nil {
					return
				}
				e.mu.Lock()
				e.sinkHits++
				e.mu.Unlock()
			}
		}()
	}

	e.auditFile = filepath.Join(root, "audit.jsonl")
	daemon := exec.Command(filepath.Join(e.bin, "placeholderd"),
		"--upstream", e.provider.Listener.Addr().String(), "--upstream-ca", caFile, "--audit", e.auditFile, "--canary", canary)
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

// run executes argv inside the sandbox through `keylatch run --tier D3`.
func (e *placeholderEnv) run(t *testing.T, conn string, tools []string, env map[string]string, argv ...string) (string, string, int) {
	t.Helper()
	dirs := []string{e.bin}
	for _, tool := range tools {
		if p, err := exec.LookPath(tool); err == nil {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	args := []string{
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/tmp/home",
		"--unshare-pid", "--unshare-net", "--unshare-ipc", "--die-with-parent", "--clearenv",
		"--ro-bind", e.bin, e.bin, "--bind", e.runtimeDir, e.runtimeDir,
		"--setenv", "PATH", strings.Join(append(dirs, "/usr/bin", "/bin"), ":"),
		"--setenv", "HOME", "/tmp/home", "--setenv", "XDG_RUNTIME_DIR", e.runtimeDir,
	}
	for k, v := range env {
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--", "keylatch", "run", "--tier", "D3", conn, "--")
	cmd := exec.Command("bwrap", append(args, argv...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

type auditLine struct {
	Action  string         `json:"action"`
	Outcome string         `json:"outcome"`
	Extra   map[string]any `json:"extra"`
}

func (e *placeholderEnv) audit(t *testing.T) []auditLine {
	t.Helper()
	f, err := os.Open(e.auditFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []auditLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l auditLine
		if err := json.Unmarshal(sc.Bytes(), &l); err == nil {
			out = append(out, l)
		}
	}
	return out
}

func (e *placeholderEnv) count(t *testing.T, action string) int {
	n := 0
	for _, l := range e.audit(t) {
		if l.Action == action {
			n++
		}
	}
	return n
}

func (e *placeholderEnv) noCanaryOnDisk(t *testing.T) {
	t.Helper()
	raw, _ := os.ReadFile(e.auditFile)
	if bytes.Contains(raw, []byte(canary)) {
		t.Error("the audit log holds the credential")
	}
}

func TestPlaceholderEnvironmentHoldsOnlyPlaceholders(t *testing.T) {
	e := setupPlaceholder(t)
	script := `env; echo ---; cat /proc/self/environ | tr '\0' '\n'; echo ---;
node -e 'console.log(JSON.stringify(process.env))' 2>&1; echo ---;
python3 -c 'import os,json;print(json.dumps(dict(os.environ)))' 2>&1`
	out, errOut, code := e.run(t, "stripe", []string{"node", "python3"}, nil, "sh", "-c", script)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out, canary) || strings.Contains(errOut, canary) {
		t.Fatal("the credential reached the child")
	}
	for _, want := range []string{"STRIPE_SECRET_KEY=sk_klph_", "HTTPS_PROXY=http://127.0.0.1:", "SSL_CERT_FILE=", "NODE_EXTRA_CA_CERTS=", "REQUESTS_CA_BUNDLE=", "CURL_CA_BUNDLE=", "GIT_SSL_CAINFO=", "AWS_CA_BUNDLE=", "DENO_CERT="} {
		if !strings.Contains(out, want) {
			t.Errorf("child environment lacks %q", want)
		}
	}
	if strings.Count(out, "sk_klph_") < 4 {
		t.Errorf("expected the placeholder in every dump, got %d", strings.Count(out, "sk_klph_"))
	}
	e.noCanaryOnDisk(t)
}

func TestPlaceholderExfiltrationRoutesAreClosed(t *testing.T) {
	e := setupPlaceholder(t)
	out, errOut, code := e.run(t, "stripe", nil, nil, filepath.Join(e.bin, "probe"), "exfil", e.sinkAddr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 12 {
		t.Fatalf("probe output too short: %q", out)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, "=blocked") {
			t.Errorf("%s", l)
		}
	}
	time.Sleep(200 * time.Millisecond)
	e.mu.Lock()
	hits := e.sinkHits
	e.mu.Unlock()
	if hits != 0 {
		t.Errorf("the sink received %d connections", hits)
	}
	if n := len(e.providerHits()); n != 0 {
		t.Errorf("a provider saw %d requests from the exfiltration attempts", n)
	}
	if e.count(t, "egress.denied") == 0 {
		t.Error("no egress.denied event")
	}
	e.noCanaryOnDisk(t)
}

func TestPlaceholderSlotAndHostRules(t *testing.T) {
	probe := func(e *placeholderEnv) string { return filepath.Join(e.bin, "probe") }
	type kase struct {
		name   string
		script func(e *placeholderEnv) []string
		want   string
		action string
	}
	cases := []kase{
		{"bound slot", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://api.stripe.com/v1/balance", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY"}
		}, "status=200 proto=HTTP/2.0", ""},
		{"other header", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://api.stripe.com/v1/x", "-H", "X-Other=$STRIPE_SECRET_KEY"}
		}, "placeholder_misuse", "placeholder.misuse"},
		{"body", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "POST", "https://api.stripe.com/v1/x", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY", "-d", `{"k":"$STRIPE_SECRET_KEY"}`}
		}, "placeholder_misuse", "placeholder.misuse"},
		{"query", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://files.stripe.com/v1/x?key=$STRIPE_SECRET_KEY"}
		}, "placeholder_misuse", "placeholder.misuse"},
		{"wrong host", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://api.github.com/user", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY"}
		}, "error:", "egress.denied"},
		{"redirect to another authority", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://api.stripe.com/redir", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY", "-then", "follow"}
		}, "placeholder_misuse", "placeholder.misuse"},
		{"authority differs from the tunnel (h2 coalescing)", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://api.stripe.com/v1/x", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY", "-authority", "api.github.com"}
		}, "placeholder_misuse", "placeholder.misuse"},
		{"CONNECT to an IP", func(e *placeholderEnv) []string {
			return []string{probe(e), "request", "GET", "https://203.0.113.9/x", "-H", "Authorization=Bearer $STRIPE_SECRET_KEY"}
		}, "error:", "egress.denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setupPlaceholder(t)
			argv := tc.script(e)
			out, errOut, code := e.run(t, "stripe", nil, nil, "sh", "-c", shellJoin(argv))
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if !strings.Contains(out, tc.want) || strings.Contains(out, canary) {
				t.Fatalf("output %q, want %q and no credential", out, tc.want)
			}
			hits := e.providerHits()
			if tc.action == "" {
				if len(hits) != 1 || hits[0].Auth != "Bearer "+canary || hits[0].Host != "api.stripe.com" || hits[0].Proto != "HTTP/2.0" {
					t.Fatalf("provider hits %+v", hits)
				}
				return
			}
			for _, h := range hits {
				if strings.Contains(h.Body, "klph_") || strings.Contains(h.Query, "klph_") || strings.Contains(h.Auth, "klph_") {
					t.Errorf("a placeholder reached the provider: %+v", h)
				}
				if h.Host != "api.stripe.com" || h.Path == "/x" || h.Path == "/v1/x" {
					t.Errorf("a refused request reached the provider: %+v", h)
				}
			}
			if e.count(t, tc.action) == 0 {
				t.Errorf("no %s event in %+v", tc.action, e.audit(t))
			}
			e.noCanaryOnDisk(t)
		})
	}
}

func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if strings.Contains(a, "$") {
			parts[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		} else {
			parts[i] = "'" + a + "'"
		}
	}
	return strings.Join(parts, " ")
}

func TestPlaceholderToolsWorkUnmodified(t *testing.T) {
	type tool struct {
		name, conn string
		tools      []string
		argv       []string
		env        map[string]string
		wantOut    string
		check      func(t *testing.T, h hit)
	}
	bearer := func(t *testing.T, h hit) {
		if h.Auth != "Bearer "+canary && h.Auth != "token "+canary {
			t.Errorf("authorization %q", h.Auth)
		}
	}
	tools := []tool{
		{"gh", "github", []string{"gh"}, []string{"gh", "api", "user"}, map[string]string{"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}, "octo", bearer},
		{"vercel", "vercel", []string{"vercel", "node"}, []string{"vercel", "whoami"}, map[string]string{"VERCEL_TELEMETRY_DISABLED": "1", "NO_UPDATE_NOTIFIER": "1", "CI": "1"}, "octo", bearer},
		{"curl as the stripe stand-in", "stripe", []string{"curl"}, []string{"sh", "-c", `curl -sS -u "$STRIPE_SECRET_KEY:" https://api.stripe.com/v1/balance`}, nil, `"ok":true`, func(t *testing.T, h hit) {
			user, _, _ := strings.Cut(decodeBasic(h.Auth), ":")
			if user != canary {
				t.Errorf("basic user %q", user)
			}
		}},
		{"node fetch", "openai", []string{"node"}, []string{"node", "-e", `fetch('https://api.openai.com/v1/models',{headers:{Authorization:'Bearer '+process.env.OPENAI_API_KEY}}).then(r=>r.text()).then(console.log)`}, nil, `"ok":true`, bearer},
		{"python requests", "anthropic", []string{"python3"}, []string{"python3", "-c", `import requests,os;print(requests.get('https://api.anthropic.com/v1/models',headers={'x-api-key':os.environ['ANTHROPIC_API_KEY']}).text)`}, nil, `"ok":true`, func(t *testing.T, h hit) {
			if h.APIKey != canary {
				t.Errorf("x-api-key %q", h.APIKey)
			}
		}},
	}
	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exec.LookPath(tc.argv[0]); err != nil {
				t.Skipf("%s is not installed", tc.argv[0])
			}
			e := setupPlaceholder(t)
			out, errOut, code := e.run(t, tc.conn, tc.tools, tc.env, tc.argv...)
			t.Logf("%s: exit %d\nstdout: %s\nstderr: %s", tc.name, code, out, errOut)
			if code != 0 || !strings.Contains(out, tc.wantOut) {
				t.Fatalf("%s did not work through D3", tc.name)
			}
			if strings.Contains(out+errOut, canary) {
				t.Fatal("the credential reached the child")
			}
			var got []hit
			for _, h := range e.providerHits() {
				if h.Auth != "" || h.APIKey != "" {
					got = append(got, h)
				}
			}
			if len(got) == 0 {
				t.Fatal("the provider never saw an authenticated request")
			}
			tc.check(t, got[0])
			if e.count(t, "placeholder.misuse") != 0 {
				t.Error("a clean run raised a misuse event")
			}
			e.noCanaryOnDisk(t)
		})
	}
}

func decodeBasic(h string) string {
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	return string(raw)
}
