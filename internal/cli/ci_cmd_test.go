package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/ci/citest"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/testutil"
)

const ciTestAudience = "keylatch-ci"

type ciJob struct {
	issuer  *citest.Issuer
	env     map[string]string
	envFile string
	token   string
}

// setupCIJob stands up a fake Actions runner that hands out token and a config
// that trusts acme/app on main for the github-app connection.
func setupCIJob(t *testing.T, claims jwt.MapClaims) *ciJob {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	testutil.SetupHermeticConfig(t)
	job := &ciJob{issuer: citest.NewIssuer(t), env: map[string]string{}}
	job.token = job.issuer.Sign(t, claims)

	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runner-secret" || r.URL.Query().Get("audience") != ciTestAudience {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": job.token})
	}))
	t.Cleanup(runner.Close)

	dir := t.TempDir()
	job.envFile = filepath.Join(dir, "github_env")
	job.env = map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL": runner.URL, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret",
		"GITHUB_ENV": job.envFile, "RUNNER_TEMP": dir,
	}
	cfg := config.Default()
	cfg.CI = &config.CIConfig{Trust: []config.CITrust{{
		Provider: ci.GitHubActions, Audience: ciTestAudience, JWKSURL: job.issuer.JWKSURL,
		Repositories: []string{"acme/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"github-app"},
	}}}
	cfgPath := filepath.Join(dir, "config.json")
	require.NoError(t, config.Save(cfgPath, cfg))
	t.Setenv("KEYLATCH_CONFIG", cfgPath)

	prevV, prevEnv := ciVerifier, ciGetenv
	t.Cleanup(func() { ciVerifier, ciGetenv = prevV, prevEnv })
	ciVerifier = &ci.Verifier{AllowHTTP: true}
	ciGetenv = func(k string) string { return job.env[k] }
	return job
}

func runCI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	full := append([]string{"ci"}, args...)
	root.SetArgs(full)
	err := root.ExecuteContext(context.Background())
	code = ReportError(root, full, err, &errOut)
	return out.String(), errOut.String(), code
}

func TestExchangeNeverPrintsSecret(t *testing.T) {
	job := setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))
	stdout, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	require.Equal(t, exitcode.OK, code, stderr)

	sig := job.token[strings.LastIndex(job.token, ".")+1:]
	for _, out := range []string{stdout, stderr} {
		assert.NotContains(t, out, job.token)
		assert.NotContains(t, out, sig)
		assert.NotContains(t, out, "runner-secret")
	}
	var line ciLogLine
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stderr)), &line), "the job log line is JSON")
	assert.Equal(t, ciLogLine{
		Event: "ci.exchange", Outcome: "ok", Provider: ci.GitHubActions, Repository: "acme/app", Ref: "refs/heads/main",
		Environment: "prod", Connections: []string{"github-app"}, Expires: line.Expires,
	}, line)

	exported, err := os.ReadFile(job.envFile)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(exported), ci.SessionEnv+"="))
	assert.NotContains(t, string(exported), job.token)
	session, err := ci.ReadSession(strings.TrimSpace(strings.TrimPrefix(string(exported), ci.SessionEnv+"=")))
	require.NoError(t, err)
	assert.Equal(t, []string{"github-app"}, session.Connections)
}

func TestExchangeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		claims jwt.MapClaims
		reason string
		code   int
	}{
		"wrong repository": {citest.GitHubClaims(ciTestAudience, "evil/app", "refs/heads/main"), "repository_not_trusted", exitcode.PolicyDeny},
		"tag named main":   {citest.GitHubClaims(ciTestAudience, "acme/app", "refs/tags/main"), "ref_not_trusted", exitcode.PolicyDeny},
		"other audience":   {citest.GitHubClaims("other", "acme/app", "refs/heads/main"), "token_invalid", exitcode.PolicyDeny},
	} {
		t.Run(name, func(t *testing.T) {
			job := setupCIJob(t, tc.claims)
			stdout, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
			assert.Equal(t, tc.code, code)
			assert.Empty(t, stdout)
			assert.Contains(t, stderr, tc.reason)
			assert.NotContains(t, stderr, job.token)
			_, err := os.Stat(job.envFile)
			assert.True(t, os.IsNotExist(err), "nothing is exported for a refused token")
		})
	}
}

func TestExchangeFailsClosedWithoutKeys(t *testing.T) {
	job := setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))
	cfg, err := config.Load(os.Getenv("KEYLATCH_CONFIG"))
	require.NoError(t, err)
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	cfg.CI.Trust[0].JWKSURL = down.URL
	require.NoError(t, config.Save(os.Getenv("KEYLATCH_CONFIG"), cfg))

	_, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	assert.Equal(t, exitcode.BackendUnavailable, code)
	assert.Contains(t, stderr, "keys_unavailable")
	_, err = os.Stat(job.envFile)
	assert.True(t, os.IsNotExist(err))
}

func TestExchangeUsageAndTokenSources(t *testing.T) {
	job := setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))

	_, _, code := runCI(t, "exchange", "--provider", "jenkins")
	assert.Equal(t, exitcode.UserError, code)

	delete(job.env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	_, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "no_token")

	_, stderr, code = runCI(t, "exchange", "--provider", ci.GitLab)
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "no ci.trust entry")

	cfg, err := config.Load(os.Getenv("KEYLATCH_CONFIG"))
	require.NoError(t, err)
	cfg.CI.Trust = append(cfg.CI.Trust,
		config.CITrust{
			Provider: ci.GitLab, Audience: "gl", Issuer: "https://gitlab.example.com", JWKSURL: job.issuer.JWKSURL,
			Repositories: []string{"grp/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"c"},
		},
		config.CITrust{
			Provider: ci.GitLab, Audience: "gl2", Issuer: "https://gitlab.example.com", JWKSURL: job.issuer.JWKSURL,
			Repositories: []string{"grp/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"c"},
		})
	require.NoError(t, config.Save(os.Getenv("KEYLATCH_CONFIG"), cfg))
	_, _, code = runCI(t, "exchange", "--provider", ci.GitLab)
	assert.Equal(t, exitcode.UserError, code, "two audiences without --audience is ambiguous")

	job.env["MY_TOKEN"] = job.issuer.Sign(t, jwt.MapClaims{
		"iss": "https://gitlab.example.com", "aud": "gl", "exp": time.Now().Add(time.Hour).Unix(),
		"project_path": "grp/app", "ref": "main", "ref_type": "branch",
	})
	envFile := filepath.Join(t.TempDir(), "dotenv")
	_, stderr, code = runCI(t, "exchange", "--provider", ci.GitLab, "--audience", "gl", "--token-env", "MY_TOKEN", "--env-file", envFile)
	require.Equal(t, exitcode.OK, code, stderr)
	data, err := os.ReadFile(envFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), ci.SessionEnv+"=")

	_, stderr, code = runCI(t, "exchange", "--provider", ci.GitLab, "--audience", "gl", "--token-env", "UNSET")
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "no_token")
}

func TestExchangeNeedsReadableConfig(t *testing.T) {
	setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))
	require.NoError(t, os.WriteFile(os.Getenv("KEYLATCH_CONFIG"), []byte("{"), 0o600))
	_, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "trust configuration cannot be read")
}

func TestCIScopedEnforce(t *testing.T) {
	allow := func(context.Context, enforce.Request) enforce.Decision { return enforce.Decision{Allow: true} }
	env := map[string]string{}
	prev := ciGetenv
	t.Cleanup(func() { ciGetenv = prev })
	ciGetenv = func(k string) string { return env[k] }
	scoped := ciScopedEnforce(allow)
	ctx := context.Background()

	assert.True(t, scoped(ctx, enforce.Request{Connection: "anything"}).Allow, "no session leaves policy alone")

	dir := t.TempDir()
	good, err := ci.WriteSession(dir, ci.Session{Connections: []string{"github-app"}, Expires: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	env[ci.SessionEnv] = good
	assert.True(t, scoped(ctx, enforce.Request{Connection: "github-app"}).Allow)
	d := scoped(ctx, enforce.Request{Connection: "stripe"})
	assert.False(t, d.Allow)
	assert.Equal(t, "ci-session", d.Source)

	expired, err := ci.WriteSession(filepath.Join(dir, "old"), ci.Session{Connections: []string{"github-app"}, Expires: time.Now().Add(-time.Minute)})
	require.NoError(t, err)
	env[ci.SessionEnv] = expired
	assert.False(t, scoped(ctx, enforce.Request{Connection: "github-app"}).Allow, "an expired session denies")

	env[ci.SessionEnv] = filepath.Join(dir, "missing")
	d = scoped(ctx, enforce.Request{Connection: "github-app"})
	assert.False(t, d.Allow, "an unreadable session denies")
	assert.Contains(t, d.Reason, "cannot be used")
}
