package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/gateway/token"
)

const fakeInstallationToken = "ghs_fakeInstallationToken0123456789abcdefgh"

type fakeVault map[string][]byte

func (v fakeVault) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	b, ok := v[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return append([]byte(nil), b...), backend.Meta{}, nil
}

type fakeGitHub struct {
	mu      sync.Mutex
	posts   []map[string]any
	revokes int
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		g.posts = append(g.posts, req)
		var repos []map[string]any
		for _, n := range req["repositories"].([]any) {
			repos = append(repos, map[string]any{"full_name": "octo/" + n.(string)})
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        fakeInstallationToken,
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions":  req["permissions"],
			"repositories": repos,
		})
	case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
		g.revokes++
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type mintHarness struct {
	srv     *Server
	gh      *fakeGitHub
	jwt     string
	noCapJW string
}

func newMintHarness(t *testing.T, policy *config.GitHubAppMintPolicy, withAudit bool) *mintHarness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	gh := &fakeGitHub{}
	ghSrv := httptest.NewServer(gh)
	t.Cleanup(ghSrv.Close)

	vault := fakeVault{
		"default/code-hosting/github-app/config/app_id":           []byte("1234"),
		"default/code-hosting/github-app/config/installation_octo": []byte("42"),
		"default/code-hosting/github-app/private_key":             keyPEM,
	}

	dir := t.TempDir()
	signing := make([]byte, 32)
	_, _ = rand.Read(signing)
	storePath := filepath.Join(dir, "tokens.json")
	mintJWT := func(caps ...string) string {
		j, _, err := token.Mint(token.TokenSpec{Actor: "vm", Capabilities: caps, TTL: time.Hour, SigningKey: signing, StorePath: storePath})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}

	opts := ServerOptions{
		SigningKey:     signing,
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: storePath,
		Env:            func(string) string { return "" },
		Vault:          vault,
		GitHubMint: &GitHubMintOptions{
			Connection: "github-app", Namespace: "default", Category: "code-hosting",
			Policy: policy, APIBase: ghSrv.URL,
		},
	}
	if withAudit {
		auditDir := filepath.Join(dir, "audit")
		if err := os.Mkdir(auditDir, 0o700); err != nil {
			t.Fatal(err)
		}
		l, err := audit.Open(filepath.Join(auditDir, "audit.log"), make([]byte, 32), make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		opts.AuditLogger = l
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &mintHarness{srv: srv, gh: gh, jwt: mintJWT(MintGitHubCapability), noCapJW: mintJWT("openrouter.chat_completion")}
}

func (h *mintHarness) post(bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+MintGitHubPath, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.srv.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

var testMintPolicy = &config.GitHubAppMintPolicy{
	AllowRepos:        []string{"octo/app"},
	PermissionCeiling: map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"},
}

func TestMintGitHub_ReturnsScopedToken(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, true)
	w := h.post(h.jwt, `{"repository":"octo/app"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
	var reply mintGitHubReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Token != fakeInstallationToken || reply.Repository != "octo/app" || reply.ExpiresAt == "" {
		t.Fatalf("unexpected reply %+v", reply)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("token reply must not be cacheable")
	}
	if len(h.gh.posts) != 1 {
		t.Fatalf("want 1 GitHub request, got %d", len(h.gh.posts))
	}
	post := h.gh.posts[0]
	if got := post["repositories"].([]any); len(got) != 1 || got[0] != "app" {
		t.Errorf("repositories = %v, want [app]", got)
	}
	perms := post["permissions"].(map[string]any)
	if _, ok := perms["administration"]; ok || perms["contents"] != "write" || perms["pull_requests"] != "write" {
		t.Errorf("permissions = %v", perms)
	}
}

func TestMintGitHub_RequiresSessionToken(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, true)
	for name, bearer := range map[string]string{"missing": "", "garbage": "not-a-jwt"} {
		if w := h.post(bearer, `{"repository":"octo/app"}`); w.Code != http.StatusUnauthorized {
			t.Errorf("%s token = %d, want 401", name, w.Code)
		}
	}
	if w := h.post(h.noCapJW, `{"repository":"octo/app"}`); w.Code != http.StatusForbidden {
		t.Errorf("token without the mint capability = %d, want 403", w.Code)
	}
	if len(h.gh.posts) != 0 {
		t.Error("GitHub must not be called for an unauthenticated request")
	}
}

func TestMintGitHub_Refusals(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"administration":       {`{"repository":"octo/app","permissions":{"administration":"write"}}`, http.StatusBadRequest},
		"administration read":  {`{"repository":"octo/app","permissions":{"administration":"read","contents":"read"}}`, http.StatusBadRequest},
		"repo not allowed":     {`{"repository":"octo/other"}`, http.StatusForbidden},
		"above ceiling":        {`{"repository":"octo/app","permissions":{"contents":"admin"}}`, http.StatusForbidden},
		"permission not given": {`{"repository":"octo/app","permissions":{"workflows":"write"}}`, http.StatusForbidden},
		"bad repository":       {`{"repository":"octo"}`, http.StatusBadRequest},
		"two repositories":     {`{"repository":"octo/app,octo/other"}`, http.StatusBadRequest},
		"unknown field":        {`{"repository":"octo/app","repositories":["a","b"]}`, http.StatusBadRequest},
		"not json":             {`repository=octo/app`, http.StatusBadRequest},
		"trailing data":        {`{"repository":"octo/app"}{}`, http.StatusBadRequest},
	}
	h := newMintHarness(t, testMintPolicy, true)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := h.post(h.jwt, tc.body)
			if w.Code != tc.want {
				t.Fatalf("got %d %s, want %d", w.Code, w.Body.String(), tc.want)
			}
			if strings.Contains(w.Body.String(), fakeInstallationToken) {
				t.Fatal("refusal leaked a token")
			}
		})
	}
	if len(h.gh.posts) != 0 {
		t.Errorf("GitHub was called %d times for refused requests", len(h.gh.posts))
	}
}

func TestMintGitHub_AdministrationDeniedEvenWhenPolicyAllowsIt(t *testing.T) {
	p := &config.GitHubAppMintPolicy{
		AllowRepos:        []string{"octo/app"},
		PermissionCeiling: map[string]string{"administration": "admin", "contents": "write"},
	}
	h := newMintHarness(t, p, true)
	if w := h.post(h.jwt, `{"repository":"octo/app","permissions":{"administration":"write"}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
	if len(h.gh.posts) != 0 {
		t.Error("GitHub must not be asked for administration")
	}
}

func TestMintGitHub_NilPolicyDenies(t *testing.T) {
	h := newMintHarness(t, nil, true)
	if w := h.post(h.jwt, `{"repository":"octo/app"}`); w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
}

func TestMintGitHub_FailsClosedWithoutAuditLog(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, false)
	w := h.post(h.jwt, `{"repository":"octo/app"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", w.Code)
	}
	if len(h.gh.posts) != 0 {
		t.Error("an unaudited mint must not reach GitHub")
	}
}

func TestMintGitHub_MissingCredential(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, true)
	h.srv.vault = fakeVault{}
	w := h.post(h.jwt, `{"repository":"octo/app"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

func TestMintGitHub_EndpointAbsentUnlessConfigured(t *testing.T) {
	dir := t.TempDir()
	s, err := New(ServerOptions{
		SigningKey: make([]byte, 32), ApprovalsDir: filepath.Join(dir, "a"),
		TokenStorePath: filepath.Join(dir, "t.json"), Env: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+MintGitHubPath, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

func TestMintGitHub_SourceCheckPrecedesAuth(t *testing.T) {
	h := newMintHarness(t, testMintPolicy, true)
	prefixes, err := ParseAllowSources([]string{"192.168.122.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.opts.AllowSources = prefixes
	h.srv.httpSrv.Handler = h.srv.allowSourceMiddleware(h.srv.httpSrv.Handler, prefixes)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+MintGitHubPath, strings.NewReader(`{"repository":"octo/app"}`))
	req.Header.Set("Authorization", "Bearer "+h.jwt)
	req.RemoteAddr = "10.1.1.1:5"
	w := httptest.NewRecorder()
	h.srv.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "source_not_allowed") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
	if len(h.gh.posts) != 0 {
		t.Error("a refused source must not reach GitHub")
	}
}
