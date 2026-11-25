package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const proxyToken = "proxy-caller-token"

// fakeUpstream stands in for GitHub: no network. respond picks the reply.
type fakeUpstream struct {
	mu      sync.Mutex
	reqs    []seenRequest
	respond func(n int, r seenRequest) (int, http.Header, string)
}

type seenRequest struct {
	Method, Host, Path, Query, Auth string
	Header                          http.Header
	Body                            string
}

func (f *fakeUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	f.mu.Lock()
	seen := seenRequest{r.Method, r.URL.Host, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Clone(), string(body)}
	f.reqs = append(f.reqs, seen)
	n := len(f.reqs)
	f.mu.Unlock()
	status, hdr, out := 200, http.Header{}, "ok"
	if f.respond != nil {
		status, hdr, out = f.respond(n, seen)
	}
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: hdr, Body: io.NopCloser(strings.NewReader(out)), Request: r}, nil
}

func (f *fakeUpstream) seen() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.reqs...)
}

type fakeMinter struct {
	mu     sync.Mutex
	n      int
	ttl    time.Duration
	failAt map[int]bool
	now    func() time.Time
}

func (m *fakeMinter) mint(context.Context) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	if m.failAt[m.n] {
		return "", time.Time{}, errors.New("github is down")
	}
	return fmt.Sprintf("ghs_tok%d", m.n), m.now().Add(m.ttl), nil
}

func (m *fakeMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

type captureAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureAudit) Emit(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

type harness struct {
	t        *testing.T
	srv      *proxy.Server
	front    *httptest.Server
	upstream *fakeUpstream
	minter   *fakeMinter
	inj      *proxy.GitHubInjector
	audit    *captureAudit
	ca       *proxy.CA
	clock    time.Time
	clockMu  sync.Mutex
}

func (h *harness) advance(d time.Duration) {
	h.clockMu.Lock()
	h.clock = h.clock.Add(d)
	h.clockMu.Unlock()
}

func (h *harness) now() time.Time {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	return h.clock
}

func newHarness(t *testing.T, repos ...string) *harness {
	t.Helper()
	return newHarnessHost(t, "github.com", repos...)
}

func newHarnessHost(t *testing.T, host string, repos ...string) *harness {
	t.Helper()
	if len(repos) == 0 {
		repos = []string{"acme/widgets", "acme/tools"}
	}
	h := &harness{t: t, upstream: &fakeUpstream{}, audit: &captureAudit{}, clock: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.minter = &fakeMinter{ttl: time.Hour, now: h.now}
	inj, err := proxy.NewGitHubInjector(host, repos, h.minter.mint)
	require.NoError(t, err)
	inj.SetClockForTest(h.now)
	h.inj = inj
	set, err := proxy.NewGitHubSet(inj)
	require.NoError(t, err)
	dir := t.TempDir()
	permitted, err := proxy.PermittedDNS([]string{host})
	require.NoError(t, err)
	ca, err := proxy.LoadOrCreateFileCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), permitted)
	require.NoError(t, err)
	h.ca = ca
	h.srv = &proxy.Server{
		Profile:           proxy.ProxyProfile{Hosts: inj.Hosts()},
		CA:                ca,
		GitHub:            set,
		Token:             proxyToken,
		AuditEmitter:      h.audit,
		UpstreamTransport: h.upstream,
	}
	h.front = httptest.NewServer(http.HandlerFunc(h.srv.ServeHTTP))
	t.Cleanup(h.front.Close)
	return h
}

// client sends HTTPS requests through the proxy with CONNECT, trusting only the proxy CA.
func (h *harness) client(proxyAuth string) *http.Client {
	pool := x509.NewCertPool()
	require.True(h.t, pool.AppendCertsFromPEM(h.ca.CertPEM()))
	u, _ := url.Parse(h.front.URL)
	hdr := http.Header{}
	if proxyAuth != "" {
		hdr.Set("Proxy-Authorization", proxyAuth)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u), ProxyConnectHeader: hdr, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) do(method, rawURL, callerAuth, body string) (*http.Response, string) {
	h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rd)
	require.NoError(h.t, err)
	if callerAuth != "" {
		req.Header.Set("Authorization", callerAuth)
	}
	resp, err := h.client("Bearer " + proxyToken).Do(req)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
}

func TestGitHubProxy_GitSmartHTTPGetsBasicAndStripsCallerAuth(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ method, url string }{
		{"GET", "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack"},
		{"GET", "https://github.com/acme/widgets/info/refs?service=git-receive-pack"},
		{"POST", "https://github.com/acme/widgets.git/git-upload-pack"},
		{"POST", "https://github.com/ACME/Widgets.git/git-receive-pack"},
	} {
		resp, _ := h.do(tc.method, tc.url, "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:placeholder")), "0000")
		assert.Equal(t, 200, resp.StatusCode, tc.url)
	}
	seen := h.upstream.seen()
	require.Len(t, seen, 4)
	for _, s := range seen {
		assert.Equal(t, basic("ghs_tok1"), s.Auth)
		assert.Equal(t, "github.com", s.Host)
		assert.Empty(t, s.Header.Get("Proxy-Authorization"))
	}
	assert.Equal(t, "service=git-upload-pack", seen[0].Query)
	assert.Equal(t, "0000", seen[2].Body)
	assert.Equal(t, 1, h.minter.count(), "one token serves every request")
}

func TestGitHubProxy_APIGraphQLAndUploadsGetBearer(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ method, url, host string }{
		{"GET", "https://api.github.com/repos/acme/widgets/pulls?state=open", "api.github.com"},
		{"POST", "https://api.github.com/repos/acme/tools/pulls", "api.github.com"},
		{"POST", "https://api.github.com/graphql", "api.github.com"},
		{"GET", "https://api.github.com/rate_limit", "api.github.com"},
		{"POST", "https://uploads.github.com/repos/acme/widgets/releases/1/assets?name=a.zip", "uploads.github.com"},
	} {
		resp, _ := h.do(tc.method, tc.url, "Bearer placeholder", "{}")
		assert.Equal(t, 200, resp.StatusCode, tc.url)
	}
	for _, s := range h.upstream.seen() {
		assert.Equal(t, "Bearer ghs_tok1", s.Auth)
	}
}

func TestGitHubProxy_RefusesOutsideRepositoryListBeforeUpstream(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ method, url, code string }{
		{"GET", "https://github.com/acme/secret.git/info/refs?service=git-upload-pack", proxy.RefusalRepository},
		{"POST", "https://github.com/other/widgets.git/git-receive-pack", proxy.RefusalOwner},
		{"GET", "https://api.github.com/repos/acme/secret/contents/x", proxy.RefusalRepository},
		{"GET", "https://api.github.com/repos/acme", proxy.RefusalRepository},
		{"POST", "https://uploads.github.com/repos/acme/secret/releases/1/assets", proxy.RefusalRepository},
		{"GET", "https://github.com/acme/widgets/archive/main.zip", proxy.RefusalRoute},
		{"GET", "https://github.com/acme/widgets.git/git-upload-pack", proxy.RefusalRoute},
		{"POST", "https://github.com/acme/widgets/info/refs", proxy.RefusalRoute},
		{"GET", "https://github.com/", proxy.RefusalRoute},
		{"GET", "https://github.com/acme/widgets/../secret/info/refs", proxy.RefusalRoute},
		{"GET", "https://github.com/acme/widgets/info/refs/../../../secret/x", proxy.RefusalRoute},
		{"DELETE", "https://api.github.com/installation/token", proxy.RefusalRoute},
		{"GET", "https://api.github.com/app", proxy.RefusalRoute},
	} {
		resp, body := h.do(tc.method, tc.url, "", "")
		assert.Equal(t, 403, resp.StatusCode, tc.url)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json", tc.url)
		assert.JSONEq(t, `{"error":"`+tc.code+`"}`, body, tc.url)
	}
	assert.Empty(t, h.upstream.seen(), "refused requests never reach upstream")
	assert.Zero(t, h.minter.count(), "refused requests never mint")
}

func TestGitHubProxy_AuthorizeRejectsEncodedPaths(t *testing.T) {
	inj, err := proxy.NewGitHubInjector("github.com", []string{"acme/widgets"}, (&fakeMinter{now: time.Now}).mint)
	require.NoError(t, err)
	for _, raw := range []string{"/acme%2Fsecret/x/info/refs", "/acme/widgets%2F..%2Fsecret/info/refs", "//acme/widgets/info/refs", "/acme/./widgets/info/refs"} {
		u, err := url.Parse("https://github.com" + raw)
		require.NoError(t, err)
		_, refusal := inj.Authorize("github.com", "GET", u)
		assert.NotEmpty(t, refusal, raw)
	}
	u, _ := url.Parse("https://github.com/acme/widgets.git/info/refs")
	scheme, refusal := inj.Authorize("github.com", "GET", u)
	assert.Equal(t, "basic", scheme)
	assert.Empty(t, refusal)
}

func TestGitHubProxy_TokenCachedThenRemintedFiveMinutesBeforeExpiry(t *testing.T) {
	h := newHarness(t)
	get := func() string {
		_, _ = h.do("GET", "https://api.github.com/user", "", "")
		s := h.upstream.seen()
		return s[len(s)-1].Auth
	}
	assert.Equal(t, "Bearer ghs_tok1", get())
	h.advance(54 * time.Minute) // 6 minutes left: still cached
	assert.Equal(t, "Bearer ghs_tok1", get())
	assert.Equal(t, 1, h.minter.count())
	h.advance(90 * time.Second) // 4m30s left: inside the window
	assert.Equal(t, "Bearer ghs_tok2", get())
	assert.Equal(t, 2, h.minter.count())
	assert.Equal(t, "Bearer ghs_tok2", get())
	assert.Equal(t, 2, h.minter.count())
}

func rejectToken(tok string) func(int, seenRequest) (int, http.Header, string) {
	return func(_ int, r seenRequest) (int, http.Header, string) {
		if r.Auth == "Bearer "+tok || r.Auth == basic(tok) {
			return 401, nil, `{"message":"Bad credentials"}`
		}
		return 200, nil, "fresh"
	}
}

func TestGitHubProxy_On401RemintsOnceAndReplaysBody(t *testing.T) {
	h := newHarness(t)
	_, _ = h.do("GET", "https://api.github.com/user", "", "") // mints tok1
	h.advance(2 * time.Minute)
	h.upstream.respond = rejectToken("ghs_tok1")

	resp, body := h.do("POST", "https://api.github.com/graphql", "", `{"query":"{viewer{login}}"}`)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "fresh", body)
	assert.Equal(t, 2, h.minter.count())
	seen := h.upstream.seen()
	require.Len(t, seen, 3)
	assert.Equal(t, "Bearer ghs_tok1", seen[1].Auth)
	assert.Equal(t, "Bearer ghs_tok2", seen[2].Auth)
	assert.Equal(t, `{"query":"{viewer{login}}"}`, seen[2].Body, "the retry carries the original body")
}

func TestGitHubProxy_401RetryIsOnceAndRateLimited(t *testing.T) {
	h := newHarness(t)
	_, _ = h.do("GET", "https://api.github.com/user", "", "")
	h.advance(2 * time.Minute)
	h.upstream.respond = func(int, seenRequest) (int, http.Header, string) { return 401, nil, "no" }
	before := len(h.upstream.seen())

	resp, _ := h.do("GET", "https://api.github.com/user", "", "")
	assert.Equal(t, 401, resp.StatusCode, "a second 401 is passed to the caller")
	assert.Equal(t, 2, h.minter.count())
	assert.Equal(t, 2, len(h.upstream.seen())-before, "one original request plus one retry")

	for range 5 {
		r, _ := h.do("GET", "https://api.github.com/user", "", "")
		assert.Equal(t, 401, r.StatusCode)
	}
	assert.Equal(t, 2, h.minter.count(), "401s within 30s of a mint never mint again")
}

func TestGitHubProxy_LargeBodyIsStreamedNotReplayed(t *testing.T) {
	h := newHarness(t)
	_, _ = h.do("GET", "https://api.github.com/user", "", "")
	h.advance(2 * time.Minute)
	h.upstream.respond = rejectToken("ghs_tok1")
	big := strings.Repeat("a", 1<<20+10)

	resp, _ := h.do("POST", "https://github.com/acme/widgets.git/git-receive-pack", "", big)

	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, 1, h.minter.count())
	seen := h.upstream.seen()
	assert.Len(t, seen[len(seen)-1].Body, len(big), "the body still reaches upstream whole")
}

func TestGitHubProxy_MintFailureAnswers503WithoutLeakingAnything(t *testing.T) {
	h := newHarness(t)
	h.minter.failAt = map[int]bool{1: true}
	resp, body := h.do("GET", "https://api.github.com/user", "", "")
	assert.Equal(t, 503, resp.StatusCode)
	assert.JSONEq(t, `{"error":"credential_unavailable"}`, body)
	assert.NotContains(t, body, "github is down")
	assert.Empty(t, h.upstream.seen())
}

func TestGitHubProxy_CallerAuth(t *testing.T) {
	h := newHarness(t)
	status := func(auth string) int {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		resp, err := h.client(auth).Do(req)
		if err != nil {
			return -1 // the tunnel was refused
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, 200, status("Bearer "+proxyToken))
	assert.Equal(t, 200, status("Basic "+base64.StdEncoding.EncodeToString([]byte("acme:"+proxyToken))))
	for _, bad := range []string{"", "Bearer wrong", "Bearer ", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:wrong")), "Basic !!!", "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyToken)), proxyToken} {
		assert.Equal(t, -1, status(bad), "auth %q", bad)
	}
	assert.Len(t, h.upstream.seen(), 2)
}

func TestGitHubProxy_UnauthenticatedLearnsNothingAboutHosts(t *testing.T) {
	h := newHarness(t)
	for _, target := range []string{"github.com:443", "example.com:443"} {
		req, _ := http.NewRequest(http.MethodConnect, h.front.URL, nil)
		req.Host = target
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equal(t, 401, resp.StatusCode)
		assert.JSONEq(t, `{"error":"unauthorized"}`, string(b))
	}
}

func TestGitHubProxy_SourceAllowlistRunsBeforeAuth(t *testing.T) {
	h := newHarness(t)
	allow := func(cidr string) func(string) bool {
		p := netip.MustParsePrefix(cidr)
		return func(remote string) bool { return gateway.SourceAllowed([]netip.Prefix{p}, remote) }
	}
	do := func(auth string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodConnect, h.front.URL, nil)
		req.Host = "github.com:443"
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	h.srv.SourceAllowed = allow("10.0.2.0/24") // the test peer is 127.0.0.1
	for _, auth := range []string{"", "Bearer " + proxyToken, "Bearer wrong"} {
		resp, body := do(auth)
		assert.Equal(t, 403, resp.StatusCode, "outside the CIDR: refused before auth (%q)", auth)
		assert.Contains(t, body, "source_not_allowed")
	}
	h.srv.SourceAllowed = allow("127.0.0.0/8")
	resp, _ := do("")
	assert.Equal(t, 401, resp.StatusCode, "inside the CIDR the proxy token is still required")
}

func TestGitHubProxy_ServeRefusals(t *testing.T) {
	inj, err := proxy.NewGitHubInjector("github.com", []string{"acme/widgets"}, (&fakeMinter{now: time.Now}).mint)
	require.NoError(t, err)
	dir := t.TempDir()
	ca, err := proxy.LoadOrCreateFileCA(filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.key"), []string{"github.com"})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = (&proxy.Server{Addr: "10.0.2.2:7879", GitHub: mustSet(t, inj), CA: ca}).Serve(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-loopback")

	err = (&proxy.Server{Addr: "10.0.2.2:7879", AllowNonLoopback: true, GitHub: mustSet(t, inj), CA: ca}).Serve(ctx)
	require.Error(t, err, "a non-loopback bind needs a source allowlist")
	assert.Contains(t, err.Error(), "non-loopback")

	err = (&proxy.Server{Addr: "127.0.0.1:0", GitHub: mustSet(t, inj)}).Serve(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a CA")
}

func TestGitHubProxy_RedirectsGoBackToTheCaller(t *testing.T) {
	h := newHarness(t)
	h.upstream.respond = func(int, seenRequest) (int, http.Header, string) {
		return 301, http.Header{"Location": {"https://github.com/acme/widgets-renamed.git/info/refs"}}, ""
	}
	resp, _ := h.do("GET", "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack", "", "")
	assert.Equal(t, 301, resp.StatusCode)
	assert.Len(t, h.upstream.seen(), 1, "the proxy did not follow the redirect")
}

func TestGitHubProxy_KeepAliveServesSeveralRequestsOnOneTunnel(t *testing.T) {
	h := newHarness(t)
	c := h.client("Bearer " + proxyToken)
	for range 3 {
		resp, err := c.Get("https://api.github.com/user")
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		assert.Equal(t, 200, resp.StatusCode)
	}
	assert.Len(t, h.upstream.seen(), 3)
}

func TestGitHubProxy_TokenNeverInAuditResponsesOrErrors(t *testing.T) {
	h := newHarness(t)
	h.inj.OnMint = func(exp time.Time, err error) {
		_ = h.srv.AuditEmitter.Emit(context.Background(), audit.Event{Action: audit.ActionMint, Outcome: audit.OutcomeOK, Extra: map[string]any{"expires_at": exp.Format(time.RFC3339)}})
	}
	var bodies strings.Builder
	for _, tc := range []struct{ method, url string }{
		{"GET", "https://api.github.com/user"},
		{"GET", "https://github.com/acme/secret.git/info/refs"},
		{"GET", "https://github.com/acme/widgets.git/info/refs"},
	} {
		resp, body := h.do(tc.method, tc.url, "Bearer ghs_tok1", "")
		bodies.WriteString(body)
		for k, vv := range resp.Header {
			bodies.WriteString(k + strings.Join(vv, ","))
		}
	}
	h.upstream.respond = func(int, seenRequest) (int, http.Header, string) { return 401, nil, "x" }
	_, b := h.do("GET", "https://api.github.com/user", "", "")
	bodies.WriteString(b)

	h.audit.mu.Lock()
	events := fmt.Sprintf("%+v", h.audit.events)
	h.audit.mu.Unlock()
	for _, leaky := range []string{"ghs_tok", "x-access-token", basic("ghs_tok1")[6:]} {
		assert.NotContains(t, events, leaky)
		assert.NotContains(t, bodies.String(), leaky)
	}
	assert.Contains(t, events, "repository_not_allowed", "denials are audited")
}

func TestGitHubProxy_NonGitHubHostsAreNotAllowed(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodConnect, h.front.URL, nil)
	req.Host = "example.com:443"
	req.Header.Set("Proxy-Authorization", "Bearer "+proxyToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)
}

func TestNewGitHubInjector_Validation(t *testing.T) {
	m := (&fakeMinter{now: time.Now}).mint
	for _, bad := range [][]string{nil, {"noslash"}, {"a/b/c"}, {"/b"}, {"a/"}} {
		_, err := proxy.NewGitHubInjector("github.com", bad, m)
		assert.Error(t, err, "%v", bad)
	}
	_, err := proxy.NewGitHubInjector("github.com", []string{"a/b"}, nil)
	assert.Error(t, err)
}

func TestFileCA_PersistsIsNameConstrainedAndKeyStaysPrivate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	ca, err := proxy.LoadOrCreateFileCA(certPath, keyPath, []string{"github.com"})
	require.NoError(t, err)

	st, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	pemBytes := ca.CertPEM()
	assert.NotContains(t, string(pemBytes), "PRIVATE")
	onDisk, _ := os.ReadFile(certPath)
	assert.Equal(t, pemBytes, onDisk)

	again, err := proxy.LoadOrCreateFileCA(certPath, keyPath, []string{"github.com"})
	require.NoError(t, err)
	assert.Equal(t, pemBytes, again.CertPEM(), "a restart keeps the certificate guests already trust")

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes))
	verify := func(host string) error {
		leaf, err := ca.CertForHost(host)
		require.NoError(t, err)
		_, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool})
		return err
	}
	assert.NoError(t, verify("github.com"))
	assert.NoError(t, verify("api.github.com"))
	assert.Error(t, verify("example.com"), "the CA cannot vouch for other hosts even if its key leaks")

	_, err = proxy.LoadOrCreateFileCA(certPath, keyPath, []string{"example.com"})
	assert.Error(t, err, "changed constraints need an explicit regeneration")
	require.NoError(t, os.Remove(keyPath))
	_, err = proxy.LoadOrCreateFileCA(certPath, keyPath, []string{"github.com"})
	assert.Error(t, err, "a missing key never silently replaces the trusted certificate")
	_, err = proxy.LoadOrCreateFileCA(certPath, keyPath, nil)
	assert.Error(t, err)
}

func TestHeaderValue(t *testing.T) {
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:T")), proxy.HeaderValue("basic", "T"))
	assert.Equal(t, "Bearer T", proxy.HeaderValue("bearer", "T"))
}

func authz(t *testing.T, inj *proxy.GitHubInjector, host, method, rawURL string) (string, string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return inj.Authorize(host, method, u)
}

func TestGitHubInjector_EnterpriseServerLayout(t *testing.T) {
	inj, err := proxy.NewGitHubInjector("ghe.example.com", []string{"acme/widgets"}, (&fakeMinter{now: time.Now}).mint)
	require.NoError(t, err)
	assert.Equal(t, []string{"ghe.example.com"}, inj.Hosts())
	assert.Equal(t, "https://ghe.example.com/api/v3", inj.APIBase())
	for _, tc := range []struct{ host, method, path, scheme, refusal string }{
		{"ghe.example.com", "GET", "/acme/widgets.git/info/refs", "basic", ""},
		{"ghe.example.com", "POST", "/acme/widgets/git-receive-pack", "basic", ""},
		{"ghe.example.com", "GET", "/api/v3/repos/acme/widgets/pulls", "bearer", ""},
		{"ghe.example.com", "GET", "/api/v3/rate_limit", "bearer", ""},
		{"ghe.example.com", "POST", "/api/graphql", "bearer", ""},
		{"ghe.example.com", "POST", "/api/uploads/repos/acme/widgets/releases/1/assets", "bearer", ""},
		{"ghe.example.com", "GET", "/api/v3/repos/acme/secret", "", proxy.RefusalRepository},
		{"ghe.example.com", "GET", "/api/uploads/repos/acme/secret/releases/1/assets", "", proxy.RefusalRepository},
		{"ghe.example.com", "GET", "/acme/secret.git/info/refs", "", proxy.RefusalRepository},
		{"ghe.example.com", "GET", "/api/v3/app", "", proxy.RefusalRoute},
		{"ghe.example.com", "GET", "/api/v3/installation/token", "", proxy.RefusalRoute},
		{"ghe.example.com", "GET", "/api/other", "", proxy.RefusalRoute},
		{"ghe.example.com", "GET", "/api/uploads", "", proxy.RefusalRoute},
		{"api.ghe.example.com", "GET", "/repos/acme/widgets", "", proxy.RefusalRoute},
		{"github.com", "GET", "/acme/widgets.git/info/refs", "", proxy.RefusalRoute},
	} {
		scheme, refusal := authz(t, inj, tc.host, tc.method, "https://"+tc.host+tc.path)
		assert.Equal(t, tc.scheme, scheme, tc.path)
		assert.Equal(t, tc.refusal, refusal, tc.host+tc.path)
	}
	assert.False(t, inj.IsGitHubHost("github.com"))
}

func TestGitHubInjector_DataResidencyLayout(t *testing.T) {
	inj, err := proxy.NewGitHubInjector("octocorp.ghe.com", []string{"acme/widgets"}, (&fakeMinter{now: time.Now}).mint)
	require.NoError(t, err)
	assert.Equal(t, []string{"octocorp.ghe.com", "api.octocorp.ghe.com", "uploads.octocorp.ghe.com"}, inj.Hosts())
	assert.Equal(t, "https://api.octocorp.ghe.com", inj.APIBase())
	for _, tc := range []struct{ host, method, path, scheme, refusal string }{
		{"octocorp.ghe.com", "GET", "/acme/widgets.git/info/refs", "basic", ""},
		{"api.octocorp.ghe.com", "GET", "/repos/acme/widgets/issues", "bearer", ""},
		{"api.octocorp.ghe.com", "POST", "/graphql", "bearer", ""},
		{"uploads.octocorp.ghe.com", "POST", "/repos/acme/widgets/releases/1/assets", "bearer", ""},
		{"api.octocorp.ghe.com", "GET", "/repos/acme/secret", "", proxy.RefusalRepository},
		{"api.github.com", "GET", "/user", "", proxy.RefusalRoute},
		{"api.other.ghe.com", "GET", "/user", "", proxy.RefusalRoute},
	} {
		scheme, refusal := authz(t, inj, tc.host, tc.method, "https://"+tc.host+tc.path)
		assert.Equal(t, tc.scheme, scheme, tc.path)
		assert.Equal(t, tc.refusal, refusal, tc.host+tc.path)
	}
}

func TestNewGitHubInjector_HostValidation(t *testing.T) {
	m := (&fakeMinter{now: time.Now}).mint
	for _, bad := range []string{"localhost", "github.com:443", "https://github.com", "a.b.ghe.com", "-x.example.com", "ex ample.com", "../x.com"} {
		_, err := proxy.NewGitHubInjector(bad, []string{"a/b"}, m)
		assert.Error(t, err, bad)
	}
	for _, good := range []string{"", "GitHub.com", "octocorp.ghe.com", "git.example.co.uk"} {
		_, err := proxy.NewGitHubInjector(good, []string{"a/b"}, m)
		assert.NoError(t, err, good)
	}
}

func TestPermittedDNS_UnionOfConfiguredHosts(t *testing.T) {
	got, err := proxy.PermittedDNS([]string{"github.com", "octocorp.ghe.com", "ghe.example.com", "github.com"})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com", "octocorp.ghe.com", "ghe.example.com"}, got)
	_, err = proxy.PermittedDNS([]string{"nodots"})
	assert.Error(t, err)
}

func TestGitHubProxy_EnterpriseServerThroughTunnel(t *testing.T) {
	h := newHarnessHost(t, "ghe.example.com", "acme/widgets")
	resp, _ := h.do("GET", "https://ghe.example.com/acme/widgets.git/info/refs?service=git-upload-pack", "Basic placeholder", "")
	assert.Equal(t, 200, resp.StatusCode)
	resp, _ = h.do("POST", "https://ghe.example.com/api/graphql", "Bearer placeholder", "{}")
	assert.Equal(t, 200, resp.StatusCode)
	_, err := h.client("Bearer " + proxyToken).Get("https://github.com/acme/widgets.git/info/refs")
	assert.Error(t, err, "a Server listener refuses the CONNECT to github.com")
	seen := h.upstream.seen()
	require.Len(t, seen, 2)
	assert.Equal(t, basic("ghs_tok1"), seen[0].Auth)
	assert.Equal(t, "Bearer ghs_tok1", seen[1].Auth)
	assert.Equal(t, "ghe.example.com", seen[1].Host)
}

func TestFileCA_ConstraintsFollowConfiguredHosts(t *testing.T) {
	dir := t.TempDir()
	ca, err := proxy.LoadOrCreateFileCA(filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.key"), []string{"github.com", "ghe.example.com"})
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.CertPEM()))
	for host, ok := range map[string]bool{"github.com": true, "api.github.com": true, "ghe.example.com": true, "evil.example.org": false, "example.com": false} {
		leaf, err := ca.CertForHost(host)
		require.NoError(t, err)
		_, verr := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool})
		assert.Equal(t, ok, verr == nil, host)
	}
}

func mustSet(t *testing.T, in ...*proxy.GitHubInjector) *proxy.GitHubSet {
	t.Helper()
	set, err := proxy.NewGitHubSet(in...)
	require.NoError(t, err)
	return set
}

// twoOwners serves acme and other from one listener; each installation mints its own token.
func twoOwners(t *testing.T) (*harness, *fakeMinter, *fakeMinter) {
	t.Helper()
	h := newHarness(t, "acme/widgets")
	mA := h.minter
	mB := &fakeMinter{ttl: time.Hour, now: h.now}
	injB, err := proxy.NewGitHubInjector("github.com", []string{"other/service"}, func(ctx context.Context) (string, time.Time, error) {
		tok, exp, err := mB.mint(ctx)
		return "B" + tok, exp, err
	})
	require.NoError(t, err)
	injB.SetClockForTest(h.now)
	h.srv.GitHub = mustSet(t, h.inj, injB)
	return h, mA, mB
}

func (h *harness) as(user, rawURL string) (*http.Response, string) {
	h.t.Helper()
	cred := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+proxyToken))
	req, _ := http.NewRequest("GET", rawURL, nil)
	resp, err := h.client(cred).Do(req)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestGitHubProxy_TwoInstallationsOnOnePort(t *testing.T) {
	h, mA, mB := twoOwners(t)

	resp, _ := h.as("acme", "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack")
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	resp, _ = h.as("OTHER", "https://github.com/other/service.git/info/refs?service=git-upload-pack")
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode, "user names are case-insensitive")
	resp, _ = h.as("other", "https://api.github.com/graphql")
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	resp, _ = h.as("acme", "https://api.github.com/graphql")
	require.NotNil(t, resp)

	seen := h.upstream.seen()
	require.Len(t, seen, 4)
	assert.Equal(t, basic("ghs_tok1"), seen[0].Auth)
	assert.Equal(t, basic("Bghs_tok1"), seen[1].Auth)
	assert.Equal(t, "Bearer Bghs_tok1", seen[2].Auth, "GraphQL uses the selected owner's token")
	assert.Equal(t, "Bearer ghs_tok1", seen[3].Auth)
	assert.Equal(t, 1, mA.count())
	assert.Equal(t, 1, mB.count(), "each installation has its own cache")
}

func TestGitHubProxy_OwnerMismatchIs403(t *testing.T) {
	h, _, _ := twoOwners(t)
	for _, tc := range []struct{ user, url string }{
		{"acme", "https://github.com/other/service.git/info/refs"},
		{"other", "https://github.com/acme/widgets.git/info/refs"},
		{"acme", "https://api.github.com/repos/other/service/pulls"},
		{"other", "https://uploads.github.com/repos/acme/widgets/releases/1/assets"},
	} {
		resp, body := h.as(tc.user, tc.url)
		require.NotNil(t, resp, tc.url)
		assert.Equal(t, 403, resp.StatusCode, tc.url)
		assert.JSONEq(t, `{"error":"owner_mismatch"}`, body, tc.url)
	}
	assert.Empty(t, h.upstream.seen())
}

func TestGitHubProxy_UnknownUserAndMissingUserAre407(t *testing.T) {
	h, mA, mB := twoOwners(t)
	_, msg := h.as("nobody", "https://github.com/acme/widgets.git/info/refs")
	assert.Contains(t, msg, "Proxy Authentication Required", "unknown user")
	_, err := h.client("Bearer " + proxyToken).Get("https://github.com/acme/widgets.git/info/refs")
	require.Error(t, err, "Bearer with two installations has no default")
	assert.Contains(t, err.Error(), "Proxy Authentication Required")
	assert.Empty(t, h.upstream.seen())
	assert.Zero(t, mA.count()+mB.count())

	h.audit.mu.Lock()
	events := fmt.Sprintf("%+v", h.audit.events)
	h.audit.mu.Unlock()
	assert.Contains(t, events, proxy.RefusalUnknownInstallation)
	assert.Contains(t, events, proxy.RefusalInstallationRequired)
}

func TestGitHubProxy_BearerSelectsTheOnlyInstallation(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do("GET", "https://api.github.com/user", "", "")
	assert.Equal(t, 200, resp.StatusCode)
}

func TestNewGitHubSet_Validation(t *testing.T) {
	m := (&fakeMinter{now: time.Now}).mint
	a, _ := proxy.NewGitHubInjector("github.com", []string{"a/x"}, m)
	a2, _ := proxy.NewGitHubInjector("github.com", []string{"a/y"}, m)
	other, _ := proxy.NewGitHubInjector("octo.ghe.com", []string{"b/x"}, m)
	_, err := proxy.NewGitHubSet()
	assert.Error(t, err)
	_, err = proxy.NewGitHubSet(a, a2)
	assert.Error(t, err, "same owner twice")
	_, err = proxy.NewGitHubSet(a, other)
	assert.Error(t, err, "different hosts")
	_, err = proxy.NewGitHubInjector("github.com", []string{"a/x", "b/y"}, m)
	assert.Error(t, err, "one installation, one owner")
}
