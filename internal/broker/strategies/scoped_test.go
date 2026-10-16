package strategies_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRoleARN = "arn:aws:iam::123456789012:role/deploy/Reader"
	testPolicy  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
	// Key-shaped fixtures are built by concatenation so scanners do not flag them.
	baseKeyID    = "AK" + "IAEXAMPLEBASE"
	sessionKeyID = "AS" + "IAEXAMPLESESSION"
)

func stsReply(role, session string, expires time.Time) string {
	return fmt.Sprintf(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/%s/%s</Arn></AssumedRoleUser>
<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>secret-example</SecretAccessKey>
<SessionToken>token-example</SessionToken><Expiration>%s</Expiration></Credentials>
</AssumeRoleResult></AssumeRoleResponse>`, role, session, sessionKeyID, expires.UTC().Format(time.RFC3339))
}

func newSTS(t *testing.T, reply func(form url.Values) (int, string)) (*strategies.AWSStsStrategy, *[]url.Values, *[]http.Header) {
	t.Helper()
	var mu sync.Mutex
	var forms []url.Values
	var headers []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		forms, headers = append(forms, form), append(headers, r.Header.Clone())
		mu.Unlock()
		status, out := reply(form)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(srv.Close)
	s := strategies.NewAWSStsStrategy(testRoleARN, "us-east-1",
		func(string) (string, string, error) { return baseKeyID, "base-secret", nil },
		strategies.WithSTSEndpoint(srv.URL), strategies.WithSTSClock(func() time.Time { return fixedNow }))
	return s, &forms, &headers
}

func TestSTSScoped(t *testing.T) {
	s, forms, headers := newSTS(t, func(f url.Values) (int, string) {
		return 200, stsReply("Reader", f.Get("RoleSessionName"), fixedNow.Add(time.Hour))
	})
	creds, err := s.MintScoped(context.Background(), "ns", strategies.AWSScope{SessionName: "run 1", SessionPolicy: testPolicy})
	require.NoError(t, err)
	assert.Equal(t, sessionKeyID, creds.AccessKeyID)
	assert.Equal(t, fixedNow.Add(time.Hour), creds.Expiration)

	require.Len(t, *forms, 1)
	f := (*forms)[0]
	assert.Equal(t, "AssumeRole", f.Get("Action"))
	assert.Equal(t, testRoleARN, f.Get("RoleArn"))
	assert.Equal(t, testPolicy, f.Get("Policy"), "the session policy is sent")
	assert.Equal(t, "3600", f.Get("DurationSeconds"))
	assert.Equal(t, "run_1", f.Get("RoleSessionName"), "characters STS rejects are replaced")
	auth := (*headers)[0].Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+baseKeyID+"/20261007/us-east-1/sts/aws4_request"), auth)
	assert.Contains(t, auth, "SignedHeaders=content-type;host;x-amz-date")
	assert.NotContains(t, auth, "base-secret")
}

func TestSTSScopedFailsClosed(t *testing.T) {
	cases := map[string]func(f url.Values) string{
		"another role":    func(f url.Values) string { return stsReply("Admin", f.Get("RoleSessionName"), fixedNow.Add(time.Hour)) },
		"another session": func(url.Values) string { return stsReply("Reader", "someone-else", fixedNow.Add(time.Hour)) },
		"outlives request": func(f url.Values) string {
			return stsReply("Reader", f.Get("RoleSessionName"), fixedNow.Add(12*time.Hour))
		},
		"already expired": func(f url.Values) string {
			return stsReply("Reader", f.Get("RoleSessionName"), fixedNow.Add(-time.Minute))
		},
		"no credentials": func(f url.Values) string {
			return `<R><AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/Reader/` + f.Get("RoleSessionName") + `</Arn></AssumedRoleUser></AssumeRoleResult></R>`
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, _ := newSTS(t, func(f url.Values) (int, string) { return 200, body(f) })
			creds, err := s.MintScoped(context.Background(), "ns", strategies.AWSScope{SessionName: "run", SessionPolicy: testPolicy, Duration: time.Hour})
			require.ErrorIs(t, err, strategies.ErrAWSScopeMismatch)
			assert.Empty(t, creds.SecretAccessKey, "nothing is returned with a mismatch")
		})
	}
}

func TestSTSScopedRefusesWhatItCannotScope(t *testing.T) {
	s, forms, _ := newSTS(t, func(url.Values) (int, string) { return 200, "" })
	for name, scope := range map[string]strategies.AWSScope{
		"no policy":       {SessionName: "run"},
		"bad policy":      {SessionName: "run", SessionPolicy: "not json"},
		"long policy":     {SessionName: "run", SessionPolicy: `{"a":"` + strings.Repeat("x", 3000) + `"}`},
		"too long":        {SessionName: "run", SessionPolicy: testPolicy, Duration: 2 * time.Hour},
		"too short":       {SessionName: "run", SessionPolicy: testPolicy, Duration: time.Minute},
		"no session name": {SessionPolicy: testPolicy},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.MintScoped(context.Background(), "ns", scope)
			require.Error(t, err)
		})
	}
	assert.Empty(t, *forms, "a request STS would honour unscoped is never sent")
}

func TestSTSHTTPError(t *testing.T) {
	s, _, _ := newSTS(t, func(url.Values) (int, string) { return 403, "" })
	_, err := s.MintScoped(context.Background(), "ns", strategies.AWSScope{SessionName: "run", SessionPolicy: testPolicy})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

type vaultFake struct {
	mu      sync.Mutex
	lease   int
	leaseID string
	revoked []string
}

func (v *vaultFake) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "vault-token", r.Header.Get("X-Vault-Token"))
		v.mu.Lock()
		defer v.mu.Unlock()
		if r.URL.Path == "/v1/sys/leases/revoke" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			v.revoked = append(v.revoked, b["lease_id"])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease_id": v.leaseID, "lease_duration": v.lease,
			"data": map[string]any{"username": "v-user", "password": "v-pass"},
		})
	}
}

func newVault(t *testing.T, v *vaultFake) *strategies.VaultDynamicSecretStrategy {
	srv := httptest.NewServer(v.handler(t))
	t.Cleanup(srv.Close)
	return strategies.NewVaultDynamicSecretStrategy(srv.URL, "database/creds/ro",
		func(string) ([]byte, error) { return []byte("vault-token"), nil })
}

func TestVaultDynamicLease(t *testing.T) {
	t.Run("a lease within the limit is returned and revocable", func(t *testing.T) {
		v := &vaultFake{lease: 1800, leaseID: "database/creds/ro/abc"}
		s := newVault(t, v)
		lease, err := s.MintScoped(context.Background(), "ns", strategies.VaultScope{})
		require.NoError(t, err)
		assert.Equal(t, "v-user", lease.Data["username"])
		require.NoError(t, s.Revoke(context.Background(), "ns", lease.LeaseID))
		assert.Equal(t, []string{"database/creds/ro/abc"}, v.revoked)
	})
	t.Run("a longer lease is revoked and refused", func(t *testing.T) {
		v := &vaultFake{lease: 86400, leaseID: "database/creds/ro/long"}
		lease, err := newVault(t, v).MintScoped(context.Background(), "ns", strategies.VaultScope{})
		require.ErrorIs(t, err, strategies.ErrVaultLeaseMismatch)
		assert.Empty(t, lease.Data)
		assert.Equal(t, []string{"database/creds/ro/long"}, v.revoked)
	})
	t.Run("the caller's own limit applies", func(t *testing.T) {
		v := &vaultFake{lease: 1800, leaseID: "database/creds/ro/mid"}
		_, err := newVault(t, v).MintScoped(context.Background(), "ns", strategies.VaultScope{MaxLease: 10 * time.Minute})
		require.ErrorIs(t, err, strategies.ErrVaultLeaseMismatch)
		assert.Len(t, v.revoked, 1)
	})
	t.Run("a secret without a lease cannot be revoked and is refused", func(t *testing.T) {
		v := &vaultFake{lease: 600}
		_, err := newVault(t, v).MintScoped(context.Background(), "ns", strategies.VaultScope{})
		require.ErrorIs(t, err, strategies.ErrVaultLeaseMismatch)
	})
	t.Run("a limit above an hour is refused", func(t *testing.T) {
		v := &vaultFake{lease: 600, leaseID: "x"}
		_, err := newVault(t, v).MintScoped(context.Background(), "ns", strategies.VaultScope{MaxLease: 2 * time.Hour})
		require.Error(t, err)
	})
}

func TestGCPImpersonationScoped(t *testing.T) {
	var got map[string]any
	var auth, path string
	reply := func(expire time.Time) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			auth, path = r.Header.Get("Authorization"), r.URL.EscapedPath()
			_ = json.NewDecoder(r.Body).Decode(&got)
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "minted-access-token", "expireTime": expire.UTC().Format(time.RFC3339)})
		}
	}
	mint := func(h http.HandlerFunc, scope strategies.GCPScope) (strategies.GCPToken, error) {
		srv := httptest.NewServer(h)
		defer srv.Close()
		s := strategies.NewGCPImpersonationStrategy("deployer@proj.iam.gserviceaccount.com",
			func(string) ([]byte, error) { return []byte("source-token"), nil }, strategies.WithGCPEndpoint(srv.URL))
		return s.MintScoped(context.Background(), "ns", scope)
	}

	tok, err := mint(reply(time.Now().Add(30*time.Minute)), strategies.GCPScope{Scopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}, Lifetime: 30 * time.Minute})
	require.NoError(t, err)
	assert.Equal(t, "minted-access-token", string(tok.AccessToken))
	assert.Equal(t, "Bearer source-token", auth)
	assert.Contains(t, path, "/serviceAccounts/deployer@proj.iam.gserviceaccount.com:generateAccessToken")
	assert.Equal(t, "1800s", got["lifetime"])
	assert.Equal(t, []any{"https://www.googleapis.com/auth/devstorage.read_only"}, got["scope"])

	_, err = mint(reply(time.Now().Add(12*time.Hour)), strategies.GCPScope{Scopes: []string{"s"}, Lifetime: time.Hour})
	require.ErrorIs(t, err, strategies.ErrGCPScopeMismatch, "a token that outlives the request is refused")

	_, err = mint(reply(time.Now().Add(time.Hour)), strategies.GCPScope{})
	require.Error(t, err, "a token without scopes is never requested")
	_, err = mint(reply(time.Now().Add(time.Hour)), strategies.GCPScope{Scopes: []string{"s"}, Lifetime: 3 * time.Hour})
	require.Error(t, err)
}

func jwtWithAudience(aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(`{"aud":"`+aud+`"}`)) + ".sig"
}

func TestAzureFederatedScoped(t *testing.T) {
	var form url.Values
	var path string
	mint := func(aud string) (strategies.AzureToken, error) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			form, _ = url.ParseQuery(string(body))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwtWithAudience(aud), "expires_in": 3599, "token_type": "Bearer"})
		}))
		defer srv.Close()
		s := strategies.NewAzureClientCredentialsStrategy("tenant-1", "client-1",
			func(string) ([]byte, error) { return []byte("client-secret"), nil }, strategies.WithAzureAuthority(srv.URL))
		return s.MintScoped(context.Background(), "ns", "api://vault-reader")
	}

	tok, err := mint("api://vault-reader")
	require.NoError(t, err)
	assert.NotEmpty(t, tok.AccessToken)
	assert.Equal(t, "/tenant-1/oauth2/v2.0/token", path)
	assert.Equal(t, "client_credentials", form.Get("grant_type"))
	assert.Equal(t, "api://vault-reader/.default", form.Get("scope"))

	_, err = mint("https://graph.microsoft.com")
	require.ErrorIs(t, err, strategies.ErrAzureScopeMismatch, "a token for another resource is refused")
}

// TestNoUnscopedStrategies fails when a strategy file is added that is not on
// the list of strategies that limit what they issue. static_gateway never
// hands its token to a command: the gateway keeps it.
func TestNoUnscopedStrategies(t *testing.T) {
	scoped := map[string]bool{
		"aws_sts.go": true, "azure_client_credentials.go": true, "gcp_impersonation.go": true,
		"github_app.go": true, "vault_dynamic.go": true,
		"oauth_refresh.go": true, "google_oauth.go": true, "microsoft_oauth.go": true,
		"static_gateway.go": true,
		// build-tag helpers, not strategies
		"endpoint_default.go": true, "endpoint_testbuild.go": true,
	}
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			assert.True(t, scoped[n], "%s is not a strategy that limits what it issues", n)
		}
	}
}

func TestOAuthScoped(t *testing.T) {
	var form url.Values
	mint := func(reply map[string]any) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			form, _ = url.ParseQuery(string(body))
			_ = json.NewEncoder(w).Encode(reply)
		}))
		defer srv.Close()
		s := strategies.NewOAuthRefreshStrategy("google", srv.URL, "id", "secret",
			func(_, _ string) ([]byte, error) { return []byte("refresh"), nil },
			strategies.WithScopes("drive.readonly", "calendar.readonly"))
		_, err := s.Exchange(context.Background(), "actor", "session", "ns")
		return err
	}

	require.NoError(t, mint(map[string]any{"access_token": "at", "expires_in": 3600, "scope": "calendar.readonly drive.readonly"}))
	assert.Equal(t, "drive.readonly calendar.readonly", form.Get("scope"))

	require.NoError(t, mint(map[string]any{"access_token": "at", "scope": "drive.readonly"}), "a narrower scope is fine")
	require.ErrorIs(t, mint(map[string]any{"access_token": "at", "scope": "drive.readonly drive"}), strategies.ErrOAuthScopeMismatch)
	require.ErrorIs(t, mint(map[string]any{"access_token": "at"}), strategies.ErrOAuthScopeMismatch, "a reply that does not report its scope cannot be verified")
}
