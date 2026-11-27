package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/ui"
)

const scRoutePath = "/api/openai/embeddings"

type scVault struct {
	values map[string][]byte
	err    error
}

func (v *scVault) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	if v.err != nil {
		return nil, backend.Meta{}, v.err
	}
	val, ok := v.values[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	out := make([]byte, len(val))
	copy(out, val)
	return out, backend.Meta{}, nil
}

type scRoundTrip func(*http.Request) (*http.Response, error)

func (f scRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type scErrReader struct{}

func (scErrReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (scErrReader) Close() error             { return nil }

type scHarness struct {
	srv      *Server
	key      []byte
	store    string
	dir      string
	metrics  *ui.MetricsCollector
	auditLog *audit.Logger
	upstream []*http.Request
	respond  func(*http.Request) (*http.Response, error)
}

func scNewHarness(t *testing.T, vault VaultReader) *scHarness {
	t.Helper()
	if vault == nil {
		vault = &scVault{values: map[string][]byte{"default/ai/openai/api_key": scFakeCredential()}}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
		dek[i] = byte(i + 7)
	}
	al, err := audit.Open(filepath.Join(auditDir, "audit.log"), salt, dek)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })

	h := &scHarness{
		key:      key,
		store:    filepath.Join(dir, "tokens.json"),
		dir:      dir,
		metrics:  &ui.MetricsCollector{},
		auditLog: al,
	}
	h.respond = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	}
	client := &http.Client{Transport: scRoundTrip(func(r *http.Request) (*http.Response, error) {
		h.upstream = append(h.upstream, r)
		return h.respond(r)
	})}

	srv, err := New(ServerOptions{
		SigningKey:         key,
		TokenStorePath:     h.store,
		ApprovalsDir:       filepath.Join(dir, "approvals"),
		Env:                func(string) string { return "" },
		Vault:              vault,
		OverrideHTTPClient: client,
		AuditLogger:        al,
		Metrics:            h.metrics,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The registry routes point at public provider hosts; a nil SSRF check keeps
	// these tests off real DNS. The SSRF check has its own tests.
	srv.ssrfGate = nil
	h.srv = srv
	return h
}

func (h *scHarness) route(t *testing.T) *route.Route {
	t.Helper()
	rt, ok := h.srv.router.Match(http.MethodPost, scRoutePath)
	if !ok {
		t.Fatalf("route %s not compiled", scRoutePath)
	}
	return rt
}

func (h *scHarness) mint(t *testing.T, mutate func(*token.TokenSpec)) string {
	t.Helper()
	spec := token.TokenSpec{
		Actor:        "agent-a",
		Capabilities: []string{"openai.embeddings"},
		TTL:          time.Hour,
		SigningKey:   h.key,
		StorePath:    h.store,
	}
	if mutate != nil {
		mutate(&spec)
	}
	s, _, err := token.Mint(spec)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return s
}

func (h *scHarness) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	if req.Host == "example.com" {
		req.Host = "127.0.0.1:7878"
	}
	rr := httptest.NewRecorder()
	h.srv.httpSrv.Handler.ServeHTTP(rr, req)
	return rr
}

func (h *scHarness) post(t *testing.T, jwtStr, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, scRoutePath, strings.NewReader(body))
	if jwtStr != "" {
		req.Header.Set("Authorization", "Bearer "+jwtStr)
	}
	return h.do(t, req)
}

func (h *scHarness) events(t *testing.T) []audit.Event {
	t.Helper()
	evs, err := h.auditLog.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return evs
}

func scErrCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e errorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return e.Error
}

func scFakeCredential() []byte {
	return []byte("cred-" + strings.Repeat("z", 24))
}

func TestHandler_SuccessInjectsCredentialAndStripsInternalHeaders(t *testing.T) {
	cred := scFakeCredential()
	h := scNewHarness(t, &scVault{values: map[string][]byte{"default/ai/openai/api_key": cred}})
	jwtStr := h.mint(t, nil)

	req := httptest.NewRequest(http.MethodPost, scRoutePath, strings.NewReader(`{"input":"x"}`))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("X-Keylatch-Trace", "internal")
	req.Header.Set("X-Request-Id", "kept")
	req.Header.Set("X-Custom", "unlisted")
	rr := h.do(t, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if len(h.upstream) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(h.upstream))
	}
	up := h.upstream[0]
	if up.URL.Scheme != "https" || up.URL.Host != "api.openai.com" {
		t.Errorf("upstream URL = %s", up.URL)
	}
	if got := up.Header.Get("Authorization"); got != "Bearer "+string(cred) {
		t.Errorf("upstream Authorization = %q", got)
	}
	if strings.Contains(up.Header.Get("Authorization"), jwtStr) {
		t.Error("gateway JWT forwarded upstream")
	}
	if up.Header.Get("X-Keylatch-Trace") != "" {
		t.Error("internal header forwarded upstream")
	}
	if up.Header.Get("X-Request-Id") != "kept" {
		t.Error("allowlisted header dropped")
	}
	if up.Header.Get("X-Custom") != "" {
		t.Error("unlisted header forwarded upstream")
	}
	if strings.Contains(rr.Body.String(), string(cred)) {
		t.Error("credential echoed to client")
	}
	if h.metrics.GatewayRequestsOK.Load() != 1 {
		t.Errorf("ok metric = %d", h.metrics.GatewayRequestsOK.Load())
	}

	evs := h.events(t)
	found := false
	for _, e := range evs {
		if e.Action == audit.ActionGatewayCall && e.Outcome == audit.OutcomeOK {
			found = true
		}
	}
	if !found {
		t.Errorf("no ok gateway audit event in %d events", len(evs))
	}
}

func TestHandler_DeniedAndErrorMetrics(t *testing.T) {
	h := scNewHarness(t, &scVault{err: errors.New("backend offline")})
	if rr := h.post(t, "", "{}"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status %d", rr.Code)
	}
	if h.metrics.GatewayRequestsDenied.Load() != 1 {
		t.Fatalf("denied metric = %d", h.metrics.GatewayRequestsDenied.Load())
	}
	rr := h.post(t, h.mint(t, nil), "{}")
	if rr.Code != http.StatusServiceUnavailable || scErrCode(t, rr) != "vault_error" {
		t.Fatalf("vault error: %d %s", rr.Code, rr.Body.String())
	}
	if h.metrics.VaultErrorsTotal.Load() != 1 || h.metrics.GatewayRequestsError.Load() != 1 {
		t.Fatalf("vault=%d error=%d", h.metrics.VaultErrorsTotal.Load(), h.metrics.GatewayRequestsError.Load())
	}
	if len(h.upstream) != 0 {
		t.Fatal("upstream called despite vault error")
	}
}

func TestHandler_CredentialNotFound(t *testing.T) {
	h := scNewHarness(t, &scVault{values: map[string][]byte{}})
	rr := h.post(t, h.mint(t, nil), "{}")
	if rr.Code != http.StatusUnauthorized || scErrCode(t, rr) != "credential_not_found" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	if len(h.upstream) != 0 {
		t.Fatal("upstream called without credential")
	}
}

func TestHandler_TokenErrorsMapToCodes(t *testing.T) {
	h := scNewHarness(t, nil)

	revoked := h.mint(t, nil)
	toks, err := token.List(token.ListOpts{}, h.store)
	if err != nil || len(toks) != 1 {
		t.Fatalf("List: %v %d", err, len(toks))
	}
	if err := token.Revoke(toks[0].ID, h.store); err != nil {
		t.Fatal(err)
	}
	if rr := h.post(t, revoked, "{}"); scErrCode(t, rr) != "token_revoked" {
		t.Errorf("revoked: %s", rr.Body.String())
	}

	exhausted := h.mint(t, func(s *token.TokenSpec) { s.MaxUses = 1 })
	if rr := h.post(t, exhausted, "{}"); rr.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", rr.Code, rr.Body.String())
	}
	if rr := h.post(t, exhausted, "{}"); rr.Code != http.StatusUnauthorized || scErrCode(t, rr) != "token_exhausted" {
		t.Errorf("second use: %d %s", rr.Code, rr.Body.String())
	}

	nonce := h.mint(t, func(s *token.TokenSpec) { s.FDNonce = []byte(strings.Repeat("n", 32)) })
	if rr := h.post(t, nonce, "{}"); scErrCode(t, rr) != "fd_nonce_mismatch" {
		t.Errorf("nonce: %s", rr.Body.String())
	}

	if rr := h.post(t, "garbage", "{}"); scErrCode(t, rr) != "token_invalid" {
		t.Errorf("garbage: %s", rr.Body.String())
	}
}

func TestHandler_UnknownRouteWithValidToken(t *testing.T) {
	h := scNewHarness(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/openai/not-an-action", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+h.mint(t, nil))
	rr := h.do(t, req)
	if rr.Code != http.StatusNotFound || scErrCode(t, rr) != "unsupported_by_keylatch_gateway" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandler_LLMSessionGates(t *testing.T) {
	llm := func(s *token.TokenSpec) { s.LLMSession = true }

	t.Run("read-class capability blocked", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.route(t).Capability = "openai.secrets.reveal"
		jwtStr := h.mint(t, func(s *token.TokenSpec) {
			llm(s)
			s.Capabilities = []string{"openai.secrets.reveal"}
		})
		rr := h.post(t, jwtStr, "{}")
		if rr.Code != http.StatusForbidden || scErrCode(t, rr) != "llm_session_read_blocked" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("route denies llm sessions", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.route(t).LLMSessionDeny = true
		rr := h.post(t, h.mint(t, llm), "{}")
		if rr.Code != http.StatusForbidden || scErrCode(t, rr) != "llm_session_deny" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		if rr := h.post(t, h.mint(t, nil), "{}"); rr.Code != http.StatusOK {
			t.Fatalf("non-llm token should pass: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("hardware approval claims are refused at mint", func(t *testing.T) {
		h := scNewHarness(t, nil)
		for name, mutate := range map[string]func(*token.TokenSpec){
			"single root": func(s *token.TokenSpec) { s.ApprovalRootID = "root-1" },
			"two person": func(s *token.TokenSpec) {
				s.ApprovalRootID = "root-1"
				s.TwoPerson = true
				s.ApprovalRootIDs = []string{"root-1", "root-2"}
			},
		} {
			spec := token.TokenSpec{
				Actor:        "agent-a",
				Capabilities: []string{"openai.embeddings"},
				TTL:          time.Hour,
				SigningKey:   h.key,
				StorePath:    h.store,
			}
			llm(&spec)
			mutate(&spec)
			if _, _, err := token.Mint(spec); !errors.Is(err, token.ErrHardwareApprovalUnsupported) {
				t.Errorf("%s: minted: %v", name, err)
			}
		}
	})
}

func TestHandler_SubstitutionHostOverrideBlocked(t *testing.T) {
	h := scNewHarness(t, nil)
	req := httptest.NewRequest(http.MethodPost, scRoutePath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+h.mint(t, nil))
	req.Host = "attacker.example"
	rr := h.do(t, req)
	if rr.Code != http.StatusBadRequest || scErrCode(t, rr) != "substitution_blocked" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	if len(h.upstream) != 0 {
		t.Fatal("upstream called")
	}
	found := false
	for _, e := range h.events(t) {
		if e.Action == audit.ActionSubstitutionBlocked && e.Outcome == audit.OutcomeDenied {
			found = true
		}
	}
	if !found {
		t.Fatal("no substitution audit event")
	}
}

func TestHandler_BodyLimits(t *testing.T) {
	h := scNewHarness(t, nil)
	h.route(t).MaxBodyBytes = 8
	rr := h.post(t, h.mint(t, nil), strings.Repeat("a", 9))
	if rr.Code != http.StatusRequestEntityTooLarge || scErrCode(t, rr) != "body_too_large" {
		t.Fatalf("got %d %s", rr.Code, rr.Body.String())
	}
	if rr := h.post(t, h.mint(t, nil), strings.Repeat("a", 8)); rr.Code != http.StatusOK {
		t.Fatalf("at limit: %d %s", rr.Code, rr.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, scRoutePath, nil)
	req.Body = scErrReader{}
	req.ContentLength = 0
	req.Header.Set("Authorization", "Bearer "+h.mint(t, nil))
	rr = h.do(t, req)
	if rr.Code != http.StatusBadRequest || scErrCode(t, rr) != "body_read_error" {
		t.Fatalf("read error: %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandler_BrokerFailures(t *testing.T) {
	t.Run("unsupported strategy never falls back", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.route(t).ExchangeStrategy = registry.ExchangeStrategy("oauth_token_exchange")
		rr := h.post(t, h.mint(t, nil), "{}")
		if rr.Code != http.StatusServiceUnavailable || scErrCode(t, rr) != "exchange_unsupported" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		if len(h.upstream) != 0 {
			t.Fatal("upstream called")
		}
	})

	t.Run("locked vault", func(t *testing.T) {
		h := scNewHarness(t, nil)
		if err := h.srv.OnVaultLock(context.Background()); err != nil {
			t.Fatal(err)
		}
		rr := h.post(t, h.mint(t, nil), "{}")
		if rr.Code != http.StatusServiceUnavailable || scErrCode(t, rr) != "vault_locked" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		if err := h.srv.OnVaultUnlock(context.Background()); err != nil {
			t.Fatal(err)
		}
		if rr := h.post(t, h.mint(t, nil), "{}"); rr.Code != http.StatusOK {
			t.Fatalf("after unlock: %d %s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandler_UpstreamFailures(t *testing.T) {
	t.Run("bad upstream host", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.route(t).UpstreamHost = "bad host"
		rr := h.post(t, h.mint(t, nil), "{}")
		if rr.Code != http.StatusInternalServerError || scErrCode(t, rr) != "upstream_build_error" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("transport error", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.respond = func(*http.Request) (*http.Response, error) { return nil, errors.New("dial refused") }
		rr := h.post(t, h.mint(t, nil), "{}")
		if rr.Code != http.StatusServiceUnavailable || scErrCode(t, rr) != "upstream_error" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
		found := false
		for _, e := range h.events(t) {
			if e.Action == audit.ActionGatewayCall && e.Outcome == audit.OutcomeError {
				found = true
			}
		}
		if !found {
			t.Fatal("no error audit event")
		}
	})

	t.Run("response read error", func(t *testing.T) {
		h := scNewHarness(t, nil)
		h.respond = func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: scErrReader{}}, nil
		}
		rr := h.post(t, h.mint(t, nil), "{}")
		if rr.Code != http.StatusBadGateway || scErrCode(t, rr) != "upstream_read_error" {
			t.Fatalf("got %d %s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandler_ResponseRedactionAndUntrustedLabel(t *testing.T) {
	h := scNewHarness(t, nil)
	rt := h.route(t)
	rt.Redaction = []registry.RedactionRule{{Pattern: `secret-[0-9]+`}}
	rt.UntrustedContentSource = "web search!"
	rt.Method = ""
	h.respond = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Header:     http.Header{"X-Upstream": {"1"}},
			Body:       io.NopCloser(strings.NewReader(`{"v":"secret-12345"}`)),
		}, nil
	}
	rr := h.post(t, h.mint(t, nil), "{}")
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "secret-12345") {
		t.Errorf("pattern not redacted: %s", body)
	}
	if !strings.HasPrefix(body, "/* keylatch:untrusted-source:websearch */\n") {
		t.Errorf("missing untrusted label: %q", body)
	}
	if rr.Header().Get("X-Upstream") != "1" {
		t.Error("upstream header not relayed")
	}
	if h.upstream[0].Method != http.MethodPost {
		t.Errorf("default upstream method = %s", h.upstream[0].Method)
	}
}

func TestInjectAuth_Placements(t *testing.T) {
	cred := scFakeCredential()
	cases := []struct {
		name      string
		placement registry.AuthPlacement
		check     func(*http.Request) bool
	}{
		{"header with scheme", registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "SSWS"},
			func(r *http.Request) bool { return r.Header.Get("Authorization") == "SSWS "+string(cred) }},
		{"bare header", registry.AuthPlacement{In: "header", Name: "X-Api-Key"},
			func(r *http.Request) bool { return r.Header.Get("X-Api-Key") == string(cred) }},
		{"query", registry.AuthPlacement{In: "query", Name: "key"},
			func(r *http.Request) bool {
				return r.URL.Query().Get("key") == string(cred) && r.URL.Query().Get("keep") == "1"
			}},
		{"body falls back to bearer", registry.AuthPlacement{In: "body", Name: "token"},
			func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+string(cred) }},
		{"unset defaults to bearer", registry.AuthPlacement{},
			func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+string(cred) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse("https://api.example.test/v1?keep=1")
			req := &http.Request{Header: http.Header{}, URL: u}
			injectAuth(req, tc.placement, cred)
			if !tc.check(req) {
				t.Fatalf("placement not applied: headers=%v url=%s", req.Header, req.URL)
			}
		})
	}

	u, _ := url.Parse("https://api.example.test/v1")
	req := &http.Request{Header: http.Header{}, URL: u}
	injectAuth(req, registry.AuthPlacement{In: "header", Name: "Authorization"}, nil)
	if len(req.Header) != 0 || req.URL.RawQuery != "" {
		t.Fatal("empty credential must not inject anything")
	}
}

func TestNew_BindPolicy(t *testing.T) {
	key := make([]byte, 32)
	noLLM := llmcontext.Lookup(func(string) string { return "" })

	if _, err := New(ServerOptions{SigningKey: key, Bind: "0.0.0.0:7878", Env: noLLM}); err == nil {
		t.Fatal("non-loopback bind accepted without opt-in")
	}
	s, err := New(ServerOptions{SigningKey: key, Bind: "0.0.0.0:7878", AllowExternalBind: true, Env: noLLM})
	if err != nil {
		t.Fatalf("opt-in external bind outside LLM session: %v", err)
	}
	if s.httpSrv.Addr != "0.0.0.0:7878" {
		t.Fatalf("addr = %q", s.httpSrv.Addr)
	}
	s, err = New(ServerOptions{SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if s.httpSrv.Addr != "127.0.0.1:7878" {
		t.Fatalf("default addr = %q", s.httpSrv.Addr)
	}
}

func TestIsLoopbackBind_BareHosts(t *testing.T) {
	cases := map[string]bool{
		"localhost":      true,
		"127.0.0.1":      true,
		"[::1]":          true,
		"::1":            true,
		"0.0.0.0":        false,
		"10.0.0.1":       false,
		"example.test":   false,
		"":               false,
		"localhost:9000": true,
	}
	for addr, want := range cases {
		if got := isLoopbackBind(addr); got != want {
			t.Errorf("isLoopbackBind(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestServe_ListenErrorReturned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	s, err := New(ServerOptions{SigningKey: make([]byte, 32), Bind: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Serve(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("want immediate listen error, got %v (ctx %v)", err, ctx.Err())
	}
}
