package placeholder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
)

const realSecret = "sk_test_REALSECRETVALUE0123456789abcdef"

type memAudit struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (m *memAudit) Emit(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("audit unavailable")
	}
	m.events = append(m.events, e)
	return nil
}

func (m *memAudit) actions(a audit.Action) []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for _, e := range m.events {
		if e.Action == a {
			out = append(out, e)
		}
	}
	return out
}

func (m *memAudit) dump() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.events)
	return string(b)
}

type staticResolver struct {
	mu    sync.Mutex
	vals  map[string]string
	calls int
}

func (r *staticResolver) Resolve(_ context.Context, _, field string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	v, ok := r.vals[field]
	if !ok {
		return nil, errors.New("no such field")
	}
	return []byte(v), nil
}

type seen struct {
	Method, Host, Proto, Path, RawQuery string
	Header                              http.Header
	Body                                []byte
}

type upstreamFake struct {
	srv  *httptest.Server
	pool *x509.CertPool
	mu   sync.Mutex
	reqs []seen
	fn   http.HandlerFunc
}

func (u *upstreamFake) requests() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.reqs...)
}

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newUpstream(t *testing.T) *upstreamFake {
	t.Helper()
	u := &upstreamFake{}
	cert := selfSigned(t, "api.stripe.com", "files.stripe.com", "other.stripe.com", "api.github.com", "github.com")
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	u.pool = x509.NewCertPool()
	u.pool.AddCert(leaf)
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seen{r.Method, r.Host, r.Proto, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		fn := u.fn
		u.mu.Unlock()
		if fn != nil {
			fn(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	u.srv.EnableHTTP2 = true
	u.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func stripeTemplate() registry.ConnectionTemplate {
	hosts := []string{"api.stripe.com", "files.stripe.com"}
	return registry.ConnectionTemplate{
		Provider: "stripe",
		Hosts:    append(hosts, "*.edge.stripe.com"),
		Slots: []registry.Slot{
			{Field: "secret_key", In: registry.SlotHeader, Name: "Authorization", Scheme: "Bearer", Hosts: hosts},
			{Field: "secret_key", In: registry.SlotBasic, Part: registry.BasicUser, Hosts: hosts},
			{Field: "secret_key", In: registry.SlotQuery, Name: "api_key", Hosts: hosts[:1]},
		},
		PlaceholderShape: registry.PlaceholderShape{Prefix: "sk_", MinLength: 32},
	}
}

type harness struct {
	t     *testing.T
	mgr   *Manager
	sess  *Session
	up    *upstreamFake
	audit *memAudit
	res   *staticResolver
	ln    net.Listener
}

type option func(*Config, *OpenRequest)

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	h := &harness{t: t, up: newUpstream(t), audit: &memAudit{}, res: &staticResolver{vals: map[string]string{"secret_key": realSecret}}}
	cfg := Config{Resolver: h.res, Audit: h.audit, Upstream: Upstream{
		Roots: h.up.pool,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, h.up.srv.Listener.Addr().String())
		},
	}}
	req := OpenRequest{Template: stripeTemplate()}
	for _, o := range opts {
		o(&cfg, &req)
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	h.mgr = mgr
	h.sess, err = mgr.Open(req)
	if err != nil {
		t.Fatal(err)
	}
	h.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.ln.Close() })
	go func() {
		for {
			c, err := h.ln.Accept()
			if err != nil {
				return
			}
			go h.sess.Serve(c)
		}
	}()
	return h
}

func (h *harness) placeholder() string { return h.sess.Placeholders()["secret_key"] }

// dialProxy opens a raw connection to the session's proxy listener.
func (h *harness) dialProxy() (net.Conn, error) {
	c, err := net.Dial("tcp", h.ln.Addr().String())
	if err == nil {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return c, err
}

func (h *harness) client(http2 bool) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(h.sess.CAPEM())
	tr := &http.Transport{
		Proxy:           func(*http.Request) (*url.URL, error) { return url.Parse("http://" + h.ln.Addr().String()) },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	if http2 {
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) do(c *http.Client, method, rawURL string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range hdr {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestSubstitutesBoundSlots(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		name := "http1"
		if http2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c := h.client(http2)
			ph := h.placeholder()

			resp, body := h.do(c, "GET", "https://api.stripe.com/v1/balance", nil, map[string]string{"Authorization": "Bearer " + ph})
			if resp.StatusCode != 200 || body != "ok" {
				t.Fatalf("bearer: %d %q", resp.StatusCode, body)
			}
			if resp.ProtoMajor != 2 && http2 {
				t.Errorf("client leg was %s, want HTTP/2", resp.Proto)
			}
			h.do(c, "GET", "https://files.stripe.com/v1/files", nil, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(ph+":"))})
			h.do(c, "GET", "https://api.stripe.com/v1/charges?limit=3&api_key="+url.QueryEscape(ph), nil, nil)

			reqs := h.up.requests()
			if len(reqs) != 3 {
				t.Fatalf("upstream saw %d requests, want 3", len(reqs))
			}
			if got := reqs[0].Header.Get("Authorization"); got != "Bearer "+realSecret {
				t.Errorf("bearer slot: %q", got)
			}
			if http2 && reqs[0].Proto != "HTTP/2.0" {
				t.Errorf("upstream leg was %s, want HTTP/2", reqs[0].Proto)
			}
			user, _, _ := strings.Cut(string(mustB64(t, strings.TrimPrefix(reqs[1].Header.Get("Authorization"), "Basic "))), ":")
			if user != realSecret {
				t.Errorf("basic slot user: %q", user)
			}
			if reqs[2].RawQuery != "limit=3&api_key="+url.QueryEscape(realSecret) {
				t.Errorf("query slot: %q", reqs[2].RawQuery)
			}
			for _, r := range reqs {
				if strings.Contains(r.Header.Get("Authorization"), "klph_") || strings.Contains(r.RawQuery, "klph_") {
					t.Errorf("placeholder reached the upstream: %+v", r)
				}
			}
			if strings.Contains(h.audit.dump(), realSecret) || strings.Contains(h.audit.dump(), ph) {
				t.Errorf("audit holds a credential or placeholder: %s", h.audit.dump())
			}
			if n := len(h.audit.actions(audit.ActionProxySubstituted)); n != 2 {
				t.Errorf("proxy.substituted events: %d, want one per host and field (2)", n)
			}
		})
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResponseNeverShowsTheRealValue(t *testing.T) {
	h := newHarness(t)
	h.up.fn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		w.Header().Set("Location", "/echo?k="+realSecret)
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, strings.Repeat("a", 40000)+realSecret+strings.Repeat("b", 10))
	}
	resp, body := h.do(h.client(false), "GET", "https://api.stripe.com/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if strings.Contains(body, realSecret) || strings.Contains(resp.Header.Get("X-Echo"), realSecret) || strings.Contains(resp.Header.Get("Location"), realSecret) {
		t.Fatalf("the real value reached the child: %q %v", body[40000:], resp.Header)
	}
	if !strings.Contains(body, h.placeholder()) {
		t.Errorf("the response body should carry the placeholder in place of the value")
	}
}

func TestMisuseIsBlockedSuspendsAndIsAudited(t *testing.T) {
	big := strings.Repeat("z", 2<<20)
	cases := []struct {
		name  string
		where string
		send  func(h *harness, c *http.Client) (*http.Response, string)
	}{
		{"other header", "header:x-forward", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder(), "X-Forward": h.placeholder()})
		}},
		{"cookie", "header:cookie", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Cookie": "s=" + h.placeholder()})
		}},
		{"wrong scheme for slot", "header:authorization", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Token " + h.placeholder()})
		}},
		{"undeclared query", "query", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://files.stripe.com/v1/x?api_key="+h.placeholder(), nil, nil)
		}},
		{"query value with extra text", "query", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x?api_key="+h.placeholder()+"x", nil, nil)
		}},
		{"path", "path", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/"+h.placeholder(), nil, nil)
		}},
		{"body", "body", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "POST", "https://api.stripe.com/v1/x", strings.NewReader(`{"key":"`+h.placeholder()+`"}`), map[string]string{"Authorization": "Bearer " + h.placeholder()})
		}},
		{"streamed body", "body", func(h *harness, c *http.Client) (*http.Response, string) {
			pr, pw := io.Pipe()
			go func() {
				_, _ = pw.Write([]byte(big))
				_, _ = pw.Write([]byte("xx" + h.placeholder()))
				_ = pw.Close()
			}()
			return h.do(c, "POST", "https://api.stripe.com/v1/x", pr, map[string]string{"Authorization": "Bearer " + h.placeholder()})
		}},
		{"base64 in header", "header:x-blob", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"X-Blob": base64.StdEncoding.EncodeToString([]byte("user:" + h.placeholder()))})
		}},
		{"basic password carrying a placeholder", "header:authorization", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(h.placeholder()+":"+h.placeholder()))})
		}},
		{"authority mismatch", "authority_mismatch:header:authorization", func(h *harness, c *http.Client) (*http.Response, string) {
			return h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Host": "api.github.com", "Authorization": "Bearer " + h.placeholder()})
		}},
	}
	for _, http2 := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name + "/http1"
			if http2 {
				name = tc.name + "/http2"
			}
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				c := h.client(http2)
				resp, body := tc.send(h, c)
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "placeholder_misuse") {
					t.Fatalf("got %d %q, want a misuse refusal", resp.StatusCode, body)
				}
				for _, r := range h.up.requests() {
					if bytes.Contains(r.Body, []byte("klph_")) || strings.Contains(r.RawQuery, "klph_") || strings.Contains(r.Path, "klph_") {
						t.Fatalf("a placeholder reached the upstream: %+v", r)
					}
				}
				ev := h.audit.actions(audit.ActionPlaceholderMisuse)
				if len(ev) != 1 {
					t.Fatalf("placeholder.misuse events: %d", len(ev))
				}
				if got := ev[0].Extra["where"]; got != tc.where {
					t.Errorf("where = %v, want %v", got, tc.where)
				}
				if !h.sess.Suspended() {
					t.Error("session was not suspended")
				}
				if strings.Contains(h.audit.dump(), h.placeholder()) || strings.Contains(h.audit.dump(), realSecret) {
					t.Errorf("audit holds a credential or placeholder")
				}
				time.Sleep(400 * time.Millisecond)
				c2 := h.client(http2)
				req, _ := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
				req.Header.Set("Authorization", "Bearer "+h.placeholder())
				if resp2, err := c2.Do(req); err == nil {
					defer func() { _ = resp2.Body.Close() }()
					if resp2.StatusCode == 200 {
						t.Error("a suspended session still substituted")
					}
				}
			})
		}
	}
}

func TestPlaceholderToAnUnboundHostIsRefused(t *testing.T) {
	h := newHarness(t)
	c := h.client(false)
	req, _ := http.NewRequest("GET", "https://evil.example/steal", nil)
	req.Header.Set("Authorization", "Bearer "+h.placeholder())
	if resp, err := c.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("CONNECT to an unbound host succeeded: %d", resp.StatusCode)
	}
	if len(h.up.requests()) != 0 {
		t.Fatal("the upstream saw a request")
	}
	if len(h.audit.actions(audit.ActionEgressDenied)) == 0 {
		t.Error("no egress.denied event")
	}
}

func TestConnectToAnIPIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, target := range []string{"https://203.0.113.9/x", "https://127.0.0.1:" + "8443/x", "https://[::1]/x", "https://2130706433/x", "https://0x7f000001/x"} {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("Authorization", "Bearer "+h.placeholder())
		if resp, err := h.client(false).Do(req); err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: tunnel opened", target)
		}
	}
	if len(h.up.requests()) != 0 {
		t.Fatal("the upstream saw a request")
	}
}

func TestPlainHTTPIsRefusedAndPlaceholderFlagged(t *testing.T) {
	h := newHarness(t)
	c := h.client(false)
	resp, body := h.do(c, "GET", "http://api.stripe.com/v1/x", nil, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "egress_denied") {
		t.Fatalf("plain http: %d %q", resp.StatusCode, body)
	}
	resp, body = h.do(c, "GET", "http://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "placeholder_misuse") || !h.sess.Suspended() {
		t.Fatalf("plain http with a placeholder: %d %q", resp.StatusCode, body)
	}
}

func TestPlaceholderAfterRedirectToAnotherAuthority(t *testing.T) {
	h := newHarness(t)
	h.up.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "https://other.stripe.com/landing", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}
	c := h.client(false)
	resp, _ := h.do(c, "GET", "https://api.stripe.com/start", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", "https://other.stripe.com/landing", nil)
	req.Header.Set("Authorization", "Bearer "+h.placeholder())
	if r, err := c.Do(req); err == nil {
		_ = r.Body.Close()
		t.Fatal("following a redirect to an unbound host opened a tunnel")
	}

	h = newHarness(t)
	h.up.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "https://files.stripe.com/landing", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}
	c = h.client(false)
	h.do(c, "GET", "https://api.stripe.com/start", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	resp, body := h.do(c, "GET", "https://files.stripe.com/landing", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "placeholder_misuse") {
		t.Fatalf("placeholder after a redirect to another authority: %d %q", resp.StatusCode, body)
	}
	if got := h.audit.actions(audit.ActionPlaceholderMisuse); len(got) != 1 || got[0].Extra["where"] != "redirect" {
		t.Fatalf("audit: %+v", got)
	}
}

func TestWebSocketIsRefusedWithAClearError(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(h.client(false), "GET", "https://api.stripe.com/ws", nil, map[string]string{
		"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": "x", "Sec-WebSocket-Version": "13",
		"Authorization": "Bearer " + h.placeholder(),
	})
	if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "websocket_unsupported") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if len(h.up.requests()) != 0 || h.res.calls != 0 {
		t.Error("an upgrade request must not reach the upstream or the store")
	}
}

func TestCredentialIsReadOnlyWhenSubstituted(t *testing.T) {
	h := newHarness(t)
	c := h.client(false)
	h.do(c, "GET", "https://api.stripe.com/v1/public", nil, nil)
	if h.res.calls != 0 {
		t.Fatalf("the store was read for a request with no placeholder")
	}
	h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	h.do(c, "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if h.res.calls != 2 {
		t.Fatalf("store reads = %d, want one per substituted request", h.res.calls)
	}
}

func TestUseLimitAndExpiry(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *OpenRequest) { c.MaxUses = 2 })
	c := h.client(false)
	hdr := func() map[string]string { return map[string]string{"Authorization": "Bearer " + h.placeholder()} }
	h.do(c, "GET", "https://api.stripe.com/a", nil, hdr())
	h.do(c, "GET", "https://api.stripe.com/b", nil, hdr())
	if resp, _ := h.do(c, "GET", "https://api.stripe.com/c", nil, hdr()); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third use: %d", resp.StatusCode)
	}

	h = newHarness(t, func(c *Config, _ *OpenRequest) { c.TTL = 300 * time.Millisecond })
	time.Sleep(500 * time.Millisecond)
	req, _ := http.NewRequest("GET", "https://api.stripe.com/a", nil)
	req.Header.Set("Authorization", "Bearer "+h.placeholder())
	if resp, err := h.client(false).Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an expired session still opened a tunnel")
	}
}

func TestAuditFailureFailsTheRequest(t *testing.T) {
	h := newHarness(t)
	h.audit.mu.Lock()
	h.audit.fail = true
	h.audit.mu.Unlock()
	resp, _ := h.do(h.client(false), "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != http.StatusServiceUnavailable || len(h.up.requests()) != 0 {
		t.Fatalf("got %d, upstream saw %d requests", resp.StatusCode, len(h.up.requests()))
	}
}

func TestManagerRequiresResolverAndAudit(t *testing.T) {
	if _, err := NewManager(Config{Audit: &memAudit{}}); !errors.Is(err, errNoResolver) {
		t.Errorf("no resolver: %v", err)
	}
	if _, err := NewManager(Config{Resolver: &staticResolver{}}); !errors.Is(err, errNoAudit) {
		t.Errorf("no audit: %v", err)
	}
	m, _ := NewManager(Config{Resolver: &staticResolver{}, Audit: &memAudit{}})
	if _, err := m.Open(OpenRequest{Template: registry.ConnectionTemplate{Provider: "x"}}); !errors.Is(err, ErrNoBinding) {
		t.Errorf("no binding: %v", err)
	}
}

func TestPlaceholderShapeAndUniqueness(t *testing.T) {
	shape := registry.PlaceholderShape{Prefix: "ghp\x5f", MinLength: 40}
	seen := map[string]bool{}
	for range 50 {
		v, err := newValue(shape)
		if err != nil {
			t.Fatal(err)
		}
		if !shape.Matches(v) || !markerRE.MatchString(v) || seen[v] {
			t.Fatalf("bad or repeated placeholder %q", v)
		}
		seen[v] = true
	}
}

func TestSessionCAIsNameConstrained(t *testing.T) {
	ca, err := newSessionCA("0123456789abcdef", []string{"api.stripe.com:443", "*.edge.stripe.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	for _, host := range []string{"api.stripe.com", "a.edge.stripe.com"} {
		l, err := ca.leaf(host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		cert, _ := x509.ParseCertificate(l.Certificate[0])
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s does not verify: %v", host, err)
		}
	}
	if _, err := ca.leaf("evil.example"); !errors.Is(err, errNotPermitted) {
		t.Errorf("leaf for an unrelated host: %v", err)
	}
	if _, err := ca.leaf("edge.stripe.com"); !errors.Is(err, errNotPermitted) {
		t.Errorf("a wildcard constraint must not cover the bare suffix: %v", err)
	}

	// A leaf for another host signed with the stolen CA key must still fail
	// verification: the constraints live in the CA certificate itself.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"evil.example"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, forged, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	fc, _ := x509.ParseCertificate(der)
	if _, err := fc.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.example"}); err == nil {
		t.Error("a certificate for an unrelated host verified under the session CA")
	}
	ipForged := *forged
	ipForged.DNSNames = nil
	ipForged.IPAddresses = []net.IP{net.ParseIP("203.0.113.9")}
	der, _ = x509.CreateCertificate(rand.Reader, &ipForged, ca.cert, &key.PublicKey, ca.key)
	fc, _ = x509.ParseCertificate(der)
	if _, err := fc.Verify(x509.VerifyOptions{Roots: roots}); err == nil {
		t.Error("an IP certificate verified under the session CA")
	}

	other, _ := newSessionCA("fedcba9876543210", []string{"api.stripe.com"}, time.Hour)
	if string(other.pem) == string(ca.pem) || other.cert.SerialNumber.Cmp(ca.cert.SerialNumber) == 0 {
		t.Error("sessions share a CA")
	}
	ca.wipe()
	if _, err := ca.leaf("api.stripe.com"); err == nil {
		t.Error("a closed session CA still issues")
	}
}

func TestSNIMustMatchTheTunnelTarget(t *testing.T) {
	h := newHarness(t)
	conn, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n")
	buf := make([]byte, 64)
	_, _ = conn.Read(buf)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(h.sess.CAPEM())
	tc := tls.Client(conn, &tls.Config{ServerName: "files.stripe.com", RootCAs: pool})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake with a different SNI succeeded")
	}
}

func TestRestrictedDestinationsAreNeverDialed(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.1.2.3", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "ff02::1"} {
		if !deniedIP(net.ParseIP(ip)) {
			t.Errorf("%s is not denied", ip)
		}
	}
	for _, ip := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if deniedIP(net.ParseIP(ip)) {
			t.Errorf("%s is denied", ip)
		}
	}
	for _, name := range []string{"localhost", "LOCALHOST.", "a.localhost", "metadata.google.internal", "ip6-localhost"} {
		if !forbiddenName(name) {
			t.Errorf("%s is not forbidden", name)
		}
	}

	var lookups int
	u := Upstream{Lookup: func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		switch host {
		case "rebind.example":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}, nil
		case "internal.example":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, errors.New("no such host")
	}}
	for _, addr := range []string{"rebind.example:443", "internal.example:443", "127.0.0.1:80", "localhost:80", "[::1]:80", "10.0.0.1:443"} {
		if c, err := u.guardedDial(context.Background(), "tcp", addr); err == nil {
			_ = c.Close()
			t.Errorf("dialed %s", addr)
		}
	}
	if err := u.checkChained(context.Background(), "internal.example"); !errors.Is(err, errForbiddenTarget) {
		t.Errorf("chained check missed a restricted resolution: %v", err)
	}
	if err := u.checkChained(context.Background(), "unresolvable.example"); err != nil {
		t.Errorf("a name only the upstream proxy resolves must pass: %v", err)
	}
}

func TestProxyResolvesNamesAndBlocksRestrictedOnes(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *OpenRequest) {
		c.Upstream.Dial = nil
		c.Upstream.Lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	})
	resp, body := h.do(h.client(false), "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "egress_denied") {
		t.Fatalf("a name that resolves to loopback: %d %q", resp.StatusCode, body)
	}
}

func TestChainsToTheCallersProxy(t *testing.T) {
	var mu sync.Mutex
	var connects []string
	var upstreamAddr atomic.Value
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		connects = append(connects, r.Host)
		mu.Unlock()
		conn, _, _ := w.(http.Hijacker).Hijack()
		defer func() { _ = conn.Close() }()
		up, err := net.Dial("tcp", upstreamAddr.Load().(string))
		if err != nil {
			return
		}
		defer func() { _ = up.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		go func() { _, _ = io.Copy(up, conn) }()
		_, _ = io.Copy(conn, up)
	}))
	defer hop.Close()

	h := newHarness(t, func(c *Config, r *OpenRequest) {
		c.Upstream.Dial = nil
		r.UpstreamProxy = hop.URL
	})
	upstreamAddr.Store(h.up.srv.Listener.Addr().String())

	resp, body := h.do(h.client(false), "GET", "https://api.stripe.com/v1/x", nil, map[string]string{"Authorization": "Bearer " + h.placeholder()})
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("through the chained proxy: %d %q", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connects) == 0 || connects[0] != "api.stripe.com:443" {
		t.Fatalf("the caller's proxy saw %v", connects)
	}
	if got := h.up.requests()[0].Header.Get("Authorization"); got != "Bearer "+realSecret {
		t.Errorf("upstream authorization %q", got)
	}
}

func TestParseChain(t *testing.T) {
	for in, ok := range map[string]bool{
		"": true, "http://127.0.0.1:3128": true, "proxy.corp:3128": true, "socks5://127.0.0.1:1080": true, "https://p:8443": true,
		"ftp://x": false, "http://": false, "file:///etc/passwd": false,
	} {
		u, err := parseChain(in)
		if (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
		if in == "" && u != nil {
			t.Error("empty must yield no proxy")
		}
	}
}

func TestSwapReaderAcrossChunks(t *testing.T) {
	swaps := []swap{{old: []byte(realSecret), new: []byte("PLACEHOLDER")}}
	src := realSecret + strings.Repeat("x", 100) + realSecret
	for step := 1; step < 80; step += 7 {
		r := newSwapReader(iotestOneByte(strings.NewReader(src), step), swaps)
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), realSecret) || strings.Count(string(out), "PLACEHOLDER") != 2 {
			t.Fatalf("step %d: %q", step, out)
		}
	}
}

type stepReader struct {
	r    io.Reader
	step int
}

func (s stepReader) Read(p []byte) (int, error) { return s.r.Read(p[:min(len(p), s.step)]) }

func iotestOneByte(r io.Reader, step int) io.Reader { return stepReader{r, step} }

func TestFinderSeesEncodedForms(t *testing.T) {
	v, _ := newValue(registry.PlaceholderShape{Prefix: "sk_", MinLength: 32})
	f := newFinder([]string{v})
	for _, junk := range []string{"", "a", "ab", "abc", "abcd", "user:", "x:y:"} {
		for name, enc := range map[string]func([]byte) string{
			"std":   base64.StdEncoding.EncodeToString,
			"url":   base64.URLEncoding.EncodeToString,
			"raw":   func(b []byte) string { return string(b) },
			"hex":   func(b []byte) string { return strings.ToUpper(hexOf(b)) },
			"lower": func(b []byte) string { return hexOf(b) },
		} {
			data := enc([]byte(junk + v + "trailer"))
			if !f.in([]byte("prefix " + data + " suffix")) {
				t.Errorf("%s with %q lead: not found in %q", name, junk, data)
			}
		}
	}
	if f.in([]byte("an unrelated body with Authorization: Bearer abc")) {
		t.Error("false positive")
	}
	other, _ := newValue(registry.PlaceholderShape{Prefix: "sk_", MinLength: 32})
	if !f.in([]byte(other)) {
		t.Error("a placeholder from another session must be flagged too")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func FuzzPlaceholderSubstitution(f *testing.F) {
	m, err := NewManager(Config{Resolver: &staticResolver{}, Audit: &memAudit{}})
	if err != nil {
		f.Fatal(err)
	}
	s, err := m.Open(OpenRequest{Template: stripeTemplate()})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { s.Close("test") })
	ph := s.Placeholders()["secret_key"]
	f.Add("Authorization", "Bearer "+ph, "")
	f.Add("X-Other", ph, "a=b")
	f.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(ph+":")), "api_key="+ph)
	f.Add("Cookie", base64.URLEncoding.EncodeToString([]byte("zz"+ph)), "q=%6Blph_")
	f.Fuzz(func(t *testing.T, name, value, query string) {
		if strings.ContainsAny(name, "\r\n:") || name == "" {
			t.Skip()
		}
		r := &http.Request{Header: http.Header{name: {value}}, URL: &url.URL{Path: "/", RawQuery: query}}
		p, finding := s.plan(r, "api.stripe.com:443")
		if finding != nil {
			return
		}
		out := s.outbound(r, "api.stripe.com:443", p, map[string]string{"secret_key": "REALVALUE"}, nil)
		var sent []string
		for k, vv := range out.Header {
			sent = append(sent, k)
			sent = append(sent, vv...)
		}
		sent = append(sent, out.URL.RawQuery)
		for _, s2 := range sent {
			if s.finder.inString(s2) {
				t.Fatalf("a placeholder survived substitution: %q", s2)
			}
		}
	})
}
