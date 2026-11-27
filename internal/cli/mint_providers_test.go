package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConnectionPolicy replaces the operator config with one that holds the
// mint policy of a single connection.
func writeConnectionPolicy(t *testing.T, home, connection string, policy config.MintPolicy) {
	t.Helper()
	cfg := config.Default()
	cfg.Connections = map[string]config.ConnectionPolicy{connection: {Mint: &policy}}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := paths.DefaultConfig(home)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	require.NoError(t, os.Chmod(path, 0o600))
}

func putFields(env *mintEnv, provider string, cfg, secret map[string]string) {
	category := mustTemplate(provider).Category
	for k, v := range cfg {
		env.store.data[connections.ConfigFieldPath("default", category, provider, k)] = []byte(v)
	}
	for k, v := range secret {
		env.store.data[connections.SecretFieldPath("default", category, provider, k)] = []byte(v)
	}
}

func mustTemplate(provider string) registry.ConnectionTemplate {
	tmpl, err := registry.Get(provider)
	if err != nil {
		panic(err)
	}
	return tmpl
}

type vaultStub struct {
	mu      sync.Mutex
	revoked []string
}

func (v *vaultStub) server(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		defer v.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/database/creds/readonly":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"lease_id": "database/creds/readonly/L1", "lease_duration": 300,
				"data": map[string]any{"username": "v-user", "password": "v-pass"},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/leases/revoke":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			v.revoked = append(v.revoked, body["lease_id"])
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (v *vaultStub) revocations() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.revoked...)
}

func vaultMintEnv(t *testing.T) (*mintEnv, *vaultStub) {
	t.Helper()
	env := setupMint(t, defaultMintPolicy())
	stub := &vaultStub{}
	putFields(env, "hashicorp-vault", map[string]string{"vault_addr": stub.server(t)}, map[string]string{"vault_token": "root"})
	writeConnectionPolicy(t, env.home, "hashicorp-vault", config.MintPolicy{Vault: &config.VaultMintPolicy{Path: "database/creds/readonly", MaxTTL: 600}})
	return env, stub
}

func TestMintVaultThroughScope(t *testing.T) {
	env, stub := vaultMintEnv(t)
	stdout, stderr, code := runMintArgs(t, "hashicorp-vault", "--scope", "path=database/creds/readonly", "--format", "json")
	require.Equal(t, exitcode.OK, code, stderr)

	var res providerMintResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, map[string]string{"username": "v-user", "password": "v-pass"}, res.Data)
	assert.Equal(t, "database/creds/readonly/L1", res.LeaseID)
	assert.Equal(t, map[string][]string{"path": {"database/creds/readonly"}}, res.Scope)
	assert.Empty(t, res.Token)
	exp, err := time.Parse(time.RFC3339, res.ExpiresAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), exp, time.Minute)
	assert.Empty(t, stub.revocations(), "the lease is handed to the caller, so mint does not revoke it")

	events := env.recorder.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "hashicorp-vault", events[0].Extra["provider"])
	assert.Equal(t, "cli", events[0].RuntimeMode)
	line, err := json.Marshal(events[0])
	require.NoError(t, err)
	assert.NotContains(t, string(line), "v-pass")
}

func TestMintProviderRefusals(t *testing.T) {
	cases := map[string]struct {
		args []string
		code int
		want string
	}{
		"path outside the policy":       {[]string{"hashicorp-vault", "--scope", "path=secret/data/root"}, exitcode.PolicyDeny, "not the policy's path"},
		"scope key of another provider": {[]string{"hashicorp-vault", "--scope", "resource=x"}, exitcode.UserError, "--scope"},
		"malformed scope":               {[]string{"hashicorp-vault", "--scope", "path"}, exitcode.UserError, "--scope"},
		"github flags":                  {[]string{"hashicorp-vault", "--repo", "a/b"}, exitcode.UserError, "GitHub App"},
		"format":                        {[]string{"hashicorp-vault", "--format", "env"}, exitcode.UserError, "--format"},
		"aws unknown scope":             {[]string{"aws", "--scope", "x=y"}, exitcode.UserError, "--scope"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env, stub := vaultMintEnv(t)
			stdout, stderr, code := runMintArgs(t, tc.args...)
			assert.Equal(t, tc.code, code, stderr)
			assert.Contains(t, stderr, tc.want)
			assert.Empty(t, stdout)
			assert.Empty(t, stub.revocations())
			assert.Empty(t, env.recorder.Events())
		})
	}

	t.Run("no policy", func(t *testing.T) {
		env, _ := vaultMintEnv(t)
		writeOperatorPolicy(t, env.home, defaultMintPolicy(), 0o600)
		_, stderr, code := runMintArgs(t, "hashicorp-vault")
		assert.Equal(t, exitcode.PolicyDeny, code, stderr)
		assert.Contains(t, stderr, "no mint.vault policy")
	})
	t.Run("connection field missing", func(t *testing.T) {
		env, _ := vaultMintEnv(t)
		delete(env.store.data, connections.SecretFieldPath("default", mustTemplate("hashicorp-vault").Category, "hashicorp-vault", "vault_token"))
		_, stderr, code := runMintArgs(t, "hashicorp-vault")
		assert.Equal(t, 6, code, stderr)
		assert.Contains(t, stderr, "no vault_token")
	})
}

func TestMintAWSThroughScope(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	f := newAWSFixture(t)
	putFields(env, "aws", map[string]string{"access_key_id": awsTestBaseKeyID}, map[string]string{"secret_access_key": "base-secret"})
	writeConnectionPolicy(t, env.home, "aws", *f.cfg.Connections["aws"].Mint)
	prev := mintEndpoints
	mintEndpoints.AWSSTS = mintAWSSTSEndpoint
	t.Cleanup(func() { mintEndpoints = prev })
	stdout, stderr, code := runMintArgs(t, "aws", "--scope", "role_arn="+awsTestRole, "--scope", "duration=900")
	require.Equal(t, exitcode.OK, code, stderr)
	var res providerMintResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, awsTestSessionKeyID, res.Data["access_key_id"])
	assert.Equal(t, "session-secret", res.Data["secret_access_key"])
	assert.Equal(t, "session-token", res.Data["session_token"])
	assert.NotContains(t, stdout+stderr, "base-secret")
	assert.Equal(t, []string{awsTestRole}, res.Scope["role_arn"])
	form := <-f.forms
	assert.Equal(t, "900", form.Get("DurationSeconds"))
	assert.JSONEq(t, awsTestPolicy, form.Get("Policy"))
	for _, scope := range []string{"role_arn=arn:aws:iam::123456789012:role/Admin", "duration=3600", "duration=-1"} {
		stdout, stderr, code = runMintArgs(t, "aws", "--scope", scope)
		assert.Equal(t, exitcode.PolicyDeny, code, stderr)
		assert.Empty(t, stdout)
	}
	assert.Empty(t, f.forms, "refused scopes never reach STS")
}

func TestMintProviderRefusesAnAgentSession(t *testing.T) {
	env, stub := vaultMintEnv(t)
	t.Setenv("CLAUDECODE", "1")
	_, stderr, code := runMintArgs(t, "hashicorp-vault")
	assert.Equal(t, exitcode.SecurityBlock, code, stderr)
	assert.Zero(t, env.store.reads())
	assert.Empty(t, stub.revocations())
}

func TestMintGitHubAppScopeFlag(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	stdout, stderr, code := runMintArgs(t, "github-app", "--scope", "repo=patrikmichi/keylatch", "--scope", "contents=write", "--permission", "metadata=read")
	require.Equal(t, exitcode.OK, code, stderr)
	var res mintResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, "patrikmichi/keylatch", res.Repository)
	assert.Equal(t, map[string]string{"contents": "write", "metadata": "read"}, res.Permissions)
	require.Len(t, env.github.posts, 1)

	_, _, code = runMintArgs(t, "github-app", "--repo", "patrikmichi/keylatch", "--scope", "repo=patrikmichi/other", "--scope", "contents=read")
	assert.Equal(t, exitcode.UserError, code)
	_, _, code = runMintArgs(t, "github-app", "--scope", "repo", "--permission", "contents=read")
	assert.Equal(t, exitcode.UserError, code)
}

func TestMintedRunInjectsLeaseAndRevokesOnExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the command uses sh")
	}
	env, stub := vaultMintEnv(t)
	tmpl := mustTemplate("hashicorp-vault")
	driver := runner.NewMintedDriver(mintedOpener(config.Default(), env.recorder))
	var out bytes.Buffer
	receipt, err := driver.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "hashicorp-vault", Caller: callerkind.Service,
		Command: []string{"sh", "-c", `echo "user=$VAULT_SECRET_USERNAME pass=$VAULT_SECRET_PASSWORD aws=${AWS_ACCESS_KEY_ID:-unset}"`},
		Stdout:  &out, Stderr: &bytes.Buffer{},
	}, tmpl)
	require.NoError(t, err)
	assert.Zero(t, receipt.ExitCode)
	assert.Contains(t, out.String(), "user=[REDACTED] pass=[REDACTED]", "the command held the lease; the output guard masks it")
	assert.Contains(t, out.String(), "aws=unset", "a field the lease does not carry is left unset")
	assert.Equal(t, []string{"database/creds/readonly/L1"}, stub.revocations(), "the lease is revoked when the command exits")

	events := env.recorder.Events()
	require.Len(t, events, 2)
	assert.Equal(t, "minted", events[0].RuntimeMode)
	assert.Equal(t, "lease_revoked", events[1].Extra["reason"])
}

func TestMintedRunRefusesAnAgentCaller(t *testing.T) {
	env, stub := vaultMintEnv(t)
	driver := runner.NewMintedDriver(mintedOpener(config.Default(), env.recorder))
	_, err := driver.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: "hashicorp-vault", Caller: callerkind.Agent, Command: []string{"true"},
	}, mustTemplate("hashicorp-vault"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent sessions")
	assert.Empty(t, stub.revocations())
	assert.Zero(t, env.store.reads())
}

func jwtAud(aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]string{"aud": aud})
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(claims) + ".sig"
}

func TestMintAzureAndOAuthThroughScope(t *testing.T) {
	env := setupMint(t, defaultMintPolicy())
	var forms []url.Values
	var mu sync.Mutex
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		mu.Lock()
		forms = append(forms, form)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwtAud("api://reader"), "expires_in": 3000})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "oauth-at", "expires_in": 3000, "scope": "drive.readonly"})
	}))
	t.Cleanup(idp.Close)
	prev := mintEndpoints
	mintEndpoints = providermint.Endpoints{AzureAuthority: idp.URL}
	t.Cleanup(func() { mintEndpoints = prev })

	putFields(env, "azure", map[string]string{"tenant_id": "t1", "client_id": "c1"}, map[string]string{"client_secret": "s"})
	putFields(env, "oauth-refresh", map[string]string{"client_id": "c1"}, map[string]string{"client_secret": "s", "refresh_token": "r"})
	cfg := config.Default()
	cfg.Connections = map[string]config.ConnectionPolicy{
		"azure":         {Mint: &config.MintPolicy{Azure: &config.AzureMintPolicy{Resource: "api://reader"}}},
		"oauth-refresh": {Mint: &config.MintPolicy{OAuth: &config.OAuthMintPolicy{TokenEndpoint: idp.URL + "/token", Scopes: []string{"drive.readonly", "calendar.readonly"}}}},
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.DefaultConfig(env.home), data, 0o600))

	stdout, stderr, code := runMintArgs(t, "azure", "--scope", "resource=api://reader")
	require.Equal(t, exitcode.OK, code, stderr)
	var res providerMintResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, jwtAud("api://reader"), res.Token)
	assert.Equal(t, map[string][]string{"resource": {"api://reader"}}, res.Scope)

	stdout, stderr, code = runMintArgs(t, "oauth-refresh", "--scope", "scope=drive.readonly")
	require.Equal(t, exitcode.OK, code, stderr)
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	assert.Equal(t, "oauth-at", res.Token)
	assert.Equal(t, "drive.readonly", forms[len(forms)-1].Get("scope"))

	_, stderr, code = runMintArgs(t, "oauth-refresh", "--scope", "scope=contacts")
	assert.Equal(t, exitcode.PolicyDeny, code, stderr)
	_, stderr, code = runMintArgs(t, "azure", "--scope", "resource=api://other")
	assert.Equal(t, exitcode.PolicyDeny, code, stderr)

	events := env.recorder.Events()
	require.Len(t, events, 2)
	for _, e := range events {
		assert.Equal(t, audit.ActionMint, e.Action)
	}
}
