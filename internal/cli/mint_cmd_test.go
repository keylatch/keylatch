package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mintTestToken = "ghs_mintTestToken0123456789abcdefghijklmn"

// countingStore is an in-memory connections.Store that counts reads, so
// tests can prove a refusal happened before any key material was touched.
type countingStore struct {
	mu   sync.Mutex
	data map[string][]byte
	gets int
}

func (s *countingStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	v, ok := s.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return bytes.Clone(v), backend.Meta{Path: path}, nil
}

func (s *countingStore) Set(context.Context, string, []byte, backend.Meta) error {
	return errors.New("read-only")
}
func (s *countingStore) List(context.Context, string) ([]backend.Entry, error) { return nil, nil }
func (s *countingStore) Delete(context.Context, string) error                  { return nil }

func (s *countingStore) reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

type githubStub struct {
	mu      sync.Mutex
	posts   []map[string]any
	revokes []string
	widen   bool
}

func (g *githubStub) calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.posts) + len(g.revokes)
}

func (g *githubStub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/777/access_tokens":
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.posts = append(g.posts, req)
		perms := req["permissions"].(map[string]any)
		if g.widen {
			perms["workflows"] = "write"
		}
		var repos []map[string]any
		for _, n := range req["repositories"].([]any) {
			repos = append(repos, map[string]any{"full_name": "patrikmichi/" + n.(string)})
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        mintTestToken,
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions":  perms,
			"repositories": repos,
		})
	case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
		g.revokes = append(g.revokes, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type mintEnv struct {
	store    *countingStore
	github   *githubStub
	recorder *testutil.AuditRecorder
	home     string
}

func defaultMintPolicy() *config.GitHubAppMintPolicy {
	return &config.GitHubAppMintPolicy{
		DenyOwners:        []string{"abugodev"},
		AllowOwners:       []string{"patrikmichi"},
		AllowRepos:        []string{"abugodev/site"},
		PermissionCeiling: map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"},
		MaxTTL:            3600,
	}
}

func setupMint(t *testing.T, policy *config.GitHubAppMintPolicy) *mintEnv {
	t.Helper()
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv))
	testutil.ClearLLMSessionEnv(t)
	testutil.SetupHermeticConfig(t)
	t.Setenv("INVOCATION_ID", "")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	env := &mintEnv{
		store: &countingStore{data: map[string][]byte{
			connections.SecretFieldPath("default", "code-hosting", "github-app", "private_key"):              keyPEM,
			connections.ConfigFieldPath("default", "code-hosting", "github-app", "app_id"):                   []byte("1234"),
			connections.ConfigFieldPath("default", "code-hosting", "github-app", "installation_patrikmichi"): []byte("777"),
			connections.ConfigFieldPath("default", "code-hosting", "github-app", "installation_abugodev"):    []byte("777"),
		}},
		github:   &githubStub{},
		recorder: &testutil.AuditRecorder{},
		home:     t.TempDir(),
	}
	srv := httptest.NewServer(http.HandlerFunc(env.github.serve))
	t.Cleanup(srv.Close)

	writeOperatorPolicy(t, env.home, policy, 0o600)

	prevBase, prevStore, prevAudit, prevHome, prevTTY := mintGitHubAPIBase, mintStore, mintAuditEmitter, operatorHome, interactiveStdin
	t.Cleanup(func() {
		mintGitHubAPIBase, mintStore, mintAuditEmitter, operatorHome, interactiveStdin = prevBase, prevStore, prevAudit, prevHome, prevTTY
	})
	mintGitHubAPIBase = srv.URL
	mintStore = func(config.Config) connections.Store { return env.store }
	mintAuditEmitter = func() (audit.Emitter, func(), error) { return env.recorder, func() {}, nil }
	operatorHome = func() (string, error) { return env.home, nil }
	interactiveStdin = func() bool { return false }
	return env
}

func writeOperatorPolicy(t *testing.T, home string, policy *config.GitHubAppMintPolicy, mode os.FileMode) {
	t.Helper()
	cfg := config.Default()
	if policy != nil {
		cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: policy}}}
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := paths.DefaultConfig(home)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, mode))
	require.NoError(t, os.Chmod(path, mode))
}

// linkOperatorConfig replaces the operator config with a symlink to an
// identical file elsewhere; a link is refused even when its target is fine.
func linkOperatorConfig(t *testing.T, home string) {
	t.Helper()
	path := paths.DefaultConfig(home)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	target := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(target, data, 0o600))
	require.NoError(t, os.Remove(path))
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func runMintArgs(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	full := append([]string{"mint"}, args...)
	root.SetArgs(full)
	err := root.ExecuteContext(context.Background())
	code = ReportError(root, full, err, &errOut)
	return out.String(), errOut.String(), code
}

var okArgs = []string{"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents=write", "--permission", "metadata=read", "--format", "json"}

func TestMintJSONShape(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	stdout, stderr, code := runMintArgs(t, okArgs...)
	require.Equal(t, exitcode.OK, code, stderr)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(stdout), &raw))
	assert.Len(t, raw, 4)
	var res mintResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, mintTestToken, res.Token)
	assert.Equal(t, "patrikmichi/keylatch", res.Repository)
	assert.Equal(t, map[string]string{"contents": "write", "metadata": "read"}, res.Permissions)
	exp, err := time.Parse(time.RFC3339, res.ExpiresAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Hour), exp, 2*time.Minute)
	assert.Equal(t, 1, strings.Count(stdout, "\n"), "stdout carries only the JSON line")
	assert.NotContains(t, stderr, mintTestToken)

	require.Len(t, env.github.posts, 1)
	assert.Equal(t, []any{"keylatch"}, env.github.posts[0]["repositories"])
	assert.Equal(t, map[string]any{"contents": "write", "metadata": "read"}, env.github.posts[0]["permissions"])
	assert.Empty(t, env.github.revokes)
}

func TestMintOneAuditLineNoToken(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	_, stderr, code := runMintArgs(t, okArgs...)
	require.Equal(t, exitcode.OK, code, stderr)

	events := env.recorder.Events()
	require.Len(t, events, 1)
	e := events[0]
	assert.Equal(t, audit.ActionMint, e.Action)
	assert.Equal(t, audit.OutcomeOK, e.Outcome)
	assert.Equal(t, "github-app", e.Extra["connection"])
	assert.Equal(t, "patrikmichi/keylatch", e.Extra["repository"])
	assert.Equal(t, "contents=write,metadata=read", e.Extra["permissions"])
	assert.Equal(t, "host", e.Extra["caller_kind"])
	assert.NotEmpty(t, e.Extra["expires_at"])
	line, err := json.Marshal(e)
	require.NoError(t, err)
	assert.NotContains(t, string(line), mintTestToken)
	assert.NotContains(t, string(line), "ghs_")
}

func TestMintRealAuditLogHasNoToken(t *testing.T) {
	setupMint(t, defaultMintPolicy())
	l := testutil.OpenAuditLog(t)
	mintAuditEmitter = func() (audit.Emitter, func(), error) { return audit.AsEmitter(l), func() {}, nil }

	_, stderr, code := runMintArgs(t, okArgs...)
	require.Equal(t, exitcode.OK, code, stderr)

	sum, err := l.Summarize(audit.SummaryOpts{})
	require.NoError(t, err)
	data, err := os.ReadFile(l.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(data), mintTestToken)
	assert.NotZero(t, sum)
}

func TestMintFlagErrors(t *testing.T) {
	cases := map[string][]string{
		"missing repo":          {"github-app", "--permission", "contents=read"},
		"no permission":         {"github-app", "--repo", "patrikmichi/keylatch"},
		"bad permission level":  {"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents=owner"},
		"permission no level":   {"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents"},
		"duplicate permission":  {"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents=read", "--permission", "contents=write"},
		"repo without owner":    {"github-app", "--repo", "keylatch", "--permission", "contents=read"},
		"repo with extra path":  {"github-app", "--repo", "a/b/c", "--permission", "contents=read"},
		"unsupported format":    {"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents=read", "--format", "env"},
		"not a mint connection": {"github", "--repo", "patrikmichi/keylatch", "--permission", "contents=read"},
		"no connection":         {"--repo", "patrikmichi/keylatch", "--permission", "contents=read"},
		"two connections":       {"github-app", "other", "--repo", "patrikmichi/keylatch", "--permission", "contents=read"},
		"unknown flag":          {"github-app", "--repo", "patrikmichi/keylatch", "--permission", "contents=read", "--ttl", "5m"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			env := setupMint(t, defaultMintPolicy())
			stdout, _, code := runMintArgs(t, args...)
			assert.Equal(t, exitcode.UserError, code)
			assert.Empty(t, stdout)
			assert.Zero(t, env.store.reads())
			assert.Zero(t, env.github.calls())
		})
	}
}

func TestMintDenyOwnerWinsBeforeKeyRead(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	stdout, stderr, code := runMintArgs(t, "github-app", "--repo", "abugodev/site", "--permission", "contents=read", "--format", "json")
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "deny list")
	assert.Empty(t, stdout)
	assert.Zero(t, env.store.reads(), "the key backend is never touched")
	assert.Zero(t, env.github.calls())
	assert.Empty(t, env.recorder.Events())
}

func TestMintPolicyRefusalsBeforeKeyRead(t *testing.T) {
	type tc struct {
		policy  func() *config.GitHubAppMintPolicy
		args    []string
		mode    os.FileMode
		human   bool
		symlink bool
	}
	withPolicy := func(f func(p *config.GitHubAppMintPolicy)) func() *config.GitHubAppMintPolicy {
		return func() *config.GitHubAppMintPolicy { p := defaultMintPolicy(); f(p); return p }
	}
	cases := map[string]tc{
		"no policy":              {policy: func() *config.GitHubAppMintPolicy { return nil }},
		"owner not allowed":      {policy: defaultMintPolicy, args: []string{"github-app", "--repo", "someone/repo", "--permission", "contents=read"}},
		"permission not in cap":  {policy: defaultMintPolicy, args: []string{"github-app", "--repo", "patrikmichi/keylatch", "--permission", "workflows=write"}},
		"permission above cap":   {policy: defaultMintPolicy, args: []string{"github-app", "--repo", "patrikmichi/keylatch", "--permission", "metadata=write"}},
		"max_ttl over an hour":   {policy: withPolicy(func(p *config.GitHubAppMintPolicy) { p.MaxTTL = 7200 })},
		"caller kind not listed": {policy: withPolicy(func(p *config.GitHubAppMintPolicy) { p.Callers = []string{"service"} })},
		"human by default":       {policy: defaultMintPolicy, human: true},
		"config group-writable":  {policy: defaultMintPolicy, mode: 0o664},
		"config is a symlink":    {policy: defaultMintPolicy, symlink: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.mode != 0 && runtime.GOOS == "windows" {
				t.Skip("Windows has no group/other mode bits; ownership is checked instead")
			}
			env := setupMint(t, c.policy())
			if c.mode != 0 {
				writeOperatorPolicy(t, env.home, c.policy(), c.mode)
			}
			if c.symlink {
				linkOperatorConfig(t, env.home)
			}
			if c.human {
				interactiveStdin = func() bool { return true }
			}
			args := c.args
			if args == nil {
				args = okArgs
			}
			stdout, _, code := runMintArgs(t, args...)
			assert.Equal(t, exitcode.PolicyDeny, code)
			assert.Empty(t, stdout)
			assert.Zero(t, env.store.reads(), "the key backend is never touched")
			assert.Zero(t, env.github.calls())
		})
	}
}

func TestMintConfigOverrideIgnored(t *testing.T) {
	env := setupMint(t, nil)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: defaultMintPolicy()}}}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600))
	t.Setenv("KEYLATCH_CONFIG", filepath.Join(dir, "config.json"))

	_, _, code := runMintArgs(t, okArgs...)
	assert.Equal(t, exitcode.PolicyDeny, code, "a caller-chosen config cannot grant minting")
	assert.Zero(t, env.store.reads())
}

func TestMintAgentDeniedByDefault(t *testing.T) {
	p := defaultMintPolicy()
	p.Callers = []string{"service", "host", "human"}
	env := setupMint(t, p)
	t.Setenv("CLAUDECODE", "1")

	stdout, stderr, code := runMintArgs(t, okArgs...)
	assert.Equal(t, exitcode.SecurityBlock, code)
	assert.Contains(t, stderr, "agent sessions cannot mint")
	assert.Empty(t, stdout)
	assert.Zero(t, env.store.reads())
	assert.Zero(t, env.github.calls())
}

func TestMintServiceCaller(t *testing.T) {
	p := defaultMintPolicy()
	p.Callers = []string{"service"}
	env := setupMint(t, p)
	t.Setenv("INVOCATION_ID", "0123456789abcdef")

	_, stderr, code := runMintArgs(t, okArgs...)
	require.Equal(t, exitcode.OK, code, stderr)
	assert.Equal(t, "service", env.recorder.Events()[0].Extra["caller_kind"])
}

func TestMintReplyMismatchRevokes(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	env.github.widen = true

	stdout, stderr, code := runMintArgs(t, okArgs...)
	assert.Equal(t, exitcode.OperationFailed, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "revoked")
	assert.NotContains(t, stderr, mintTestToken)
	assert.Equal(t, []string{mintTestToken}, env.github.revokes)

	events := env.recorder.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.OutcomeError, events[0].Outcome)
	assert.Equal(t, "scope_mismatch", events[0].Extra["reason"])
	line, _ := json.Marshal(events[0])
	assert.NotContains(t, string(line), mintTestToken)
}

func TestMintAuditUnavailableRefusesBeforeKeyRead(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	mintAuditEmitter = func() (audit.Emitter, func(), error) { return nil, func() {}, nil }

	_, _, code := runMintArgs(t, okArgs...)
	assert.Equal(t, exitcode.SecurityBlock, code)
	assert.Zero(t, env.store.reads())
	assert.Zero(t, env.github.calls())
}

type failingEmitter struct{}

func (failingEmitter) Emit(context.Context, audit.Event) error { return errors.New("disk full") }

func TestMintAuditWriteFailureRevokes(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	mintAuditEmitter = func() (audit.Emitter, func(), error) { return failingEmitter{}, func() {}, nil }

	stdout, stderr, code := runMintArgs(t, okArgs...)
	assert.Equal(t, exitcode.OperationFailed, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "revoked")
	assert.Equal(t, []string{mintTestToken}, env.github.revokes)
}

func TestMintMissingInstallation(t *testing.T) {
	p := defaultMintPolicy()
	p.AllowOwners = append(p.AllowOwners, "keylatch")
	env := setupMint(t, p)

	stdout, stderr, code := runMintArgs(t, "github-app", "--repo", "keylatch/keylatch", "--permission", "contents=read")
	assert.Equal(t, exitCodeSecretNotFound, code)
	assert.Contains(t, stderr, "installation_keylatch")
	assert.Empty(t, stdout)
	assert.Zero(t, env.github.calls())
}

func TestMintNoTokenInRefusalOutput(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	env.github.widen = true
	stdout, stderr, _ := runMintArgs(t, okArgs...)
	for _, s := range []string{stdout, stderr} {
		assert.NotContains(t, s, mintTestToken)
		assert.NotContains(t, s, "PRIVATE KEY")
	}
}
