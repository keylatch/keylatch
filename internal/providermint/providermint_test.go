package providermint_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ns   = "default"
	conn = "work"
)

type store struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *store) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if err := ctx.Err(); err != nil {
		return nil, backend.Meta{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return []byte(v), backend.Meta{}, nil
}
func (s *store) Set(context.Context, string, []byte, backend.Meta) error { return nil }
func (s *store) List(context.Context, string) ([]backend.Entry, error)   { return nil, nil }
func (s *store) Delete(context.Context, string) error                    { return nil }

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
	cancel context.CancelFunc
}

func (r *recorder) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	if r.fail {
		return errors.New("disk full")
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) reasons() []string {
	var out []string
	for _, e := range r.events {
		reason, _ := e.Extra["reason"].(string)
		out = append(out, string(e.Outcome)+":"+reason)
	}
	return out
}

func tmpl(provider string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{Provider: provider, Category: "cloud"}
}

func fill(t *testing.T, provider string, cfg, secret map[string]string) *store {
	t.Helper()
	s := &store{m: map[string]string{}}
	for k, v := range cfg {
		s.m[connections.ConfigFieldPath(ns, tmpl(provider).Category, conn, k)] = v
	}
	for k, v := range secret {
		s.m[connections.SecretFieldPath(ns, tmpl(provider).Category, conn, k)] = v
	}
	return s
}

func policyConfig(p config.MintPolicy) config.Config {
	return config.Config{Connections: map[string]config.ConnectionPolicy{conn: {Mint: &p}}}
}

func request(provider string, st *store, cfg config.Config, em audit.Emitter) providermint.Request {
	return providermint.Request{
		Store: st, Template: tmpl(provider), Config: cfg, Connection: conn, Namespace: ns,
		Caller: mint.CallerService, Audit: em, RuntimeMode: "minted",
	}
}

func vaultServer(t *testing.T, reply map[string]any, revoked *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root-token" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/database/creds/readonly":
			_ = json.NewEncoder(w).Encode(reply)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/leases/revoke":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			*revoked = append(*revoked, body["lease_id"])
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func vaultCreds(lease int) map[string]any {
	return map[string]any{
		"lease_id": "database/creds/readonly/abc", "lease_duration": lease,
		"data": map[string]any{"username": "v-user", "password": "v-pass", "ignored": "x"},
	}
}

func vaultPolicy() config.MintPolicy {
	return config.MintPolicy{Vault: &config.VaultMintPolicy{Path: "database/creds/readonly"}}
}

func TestVaultMintRevokesOnClose(t *testing.T) {
	var revoked []string
	srv := vaultServer(t, vaultCreds(600), &revoked)
	st := fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, map[string]string{"vault_token": "root-token"})
	em := &recorder{}

	s, err := providermint.Mint(context.Background(), request(providermint.ProviderVault, st, policyConfig(vaultPolicy()), em))
	require.NoError(t, err)
	user, ok := s.Value("username")
	require.True(t, ok)
	assert.Equal(t, "v-user", string(user))
	_, ok = s.Value("ignored")
	assert.False(t, ok, "only the fields the template injects are kept")
	assert.Equal(t, "database/creds/readonly/abc", s.LeaseID)
	assert.WithinDuration(t, time.Now().Add(10*time.Minute), s.ExpiresAt, time.Minute)
	assert.Empty(t, revoked)

	require.NoError(t, s.Close())
	assert.Equal(t, []string{"database/creds/readonly/abc"}, revoked)
	assert.Equal(t, []string{"ok:", "ok:lease_revoked"}, em.reasons())
	assert.Equal(t, "path=database/creds/readonly", em.events[0].Extra["scope"])
	assert.NotContains(t, fmt.Sprint(em.events), "v-pass")

	require.NoError(t, s.Close(), "closing twice does not revoke twice")
	assert.Len(t, revoked, 1)
}

func TestVaultMintFailsClosed(t *testing.T) {
	overflowSeconds := ^uint64(0)/uint64(time.Second) + 1
	cases := []struct {
		name  string
		reply map[string]any
		want  string
	}{
		{"lease longer than the policy", vaultCreds(7200), "exceeds"},
		{"lease duration overflow", vaultCreds(int(overflowSeconds)), "exceeds"},
		{"no lease", map[string]any{"lease_duration": 60, "data": map[string]any{"username": "u"}}, "no lease"},
		{"nothing to inject", map[string]any{"lease_id": "l1", "lease_duration": 60, "data": map[string]any{"other": "x"}}, "nothing to inject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var revoked []string
			srv := vaultServer(t, tc.reply, &revoked)
			st := fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, map[string]string{"vault_token": "root-token"})
			em := &recorder{}
			s, err := providermint.Mint(context.Background(), request(providermint.ProviderVault, st, policyConfig(vaultPolicy()), em))
			require.Error(t, err)
			assert.Nil(t, s)
			assert.Contains(t, err.Error(), tc.want)
			assert.Equal(t, []string{"error:scope_mismatch"}, em.reasons())
			if id, _ := tc.reply["lease_id"].(string); id != "" {
				assert.Equal(t, []string{id}, revoked, "the lease that was issued is revoked")
			}
		})
	}
}

func TestVaultMintRevokesWhenAuditFails(t *testing.T) {
	var revoked []string
	srv := vaultServer(t, vaultCreds(60), &revoked)
	st := fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, map[string]string{"vault_token": "root-token"})
	em := &recorder{}
	// Ready passes; Emit fails after the secret exists.
	em.fail = true
	_, err := providermint.Mint(context.Background(), request(providermint.ProviderVault, st, policyConfig(vaultPolicy()), em))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit")
	assert.Equal(t, []string{"database/creds/readonly/abc"}, revoked)
}

func TestVaultMintRevokesAfterRequestCancellation(t *testing.T) {
	var revoked []string
	srv := vaultServer(t, vaultCreds(60), &revoked)
	st := fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, map[string]string{"vault_token": "root-token"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	em := &recorder{fail: true, cancel: cancel}
	_, err := providermint.Mint(ctx, request(providermint.ProviderVault, st, policyConfig(vaultPolicy()), em))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit")
	assert.Equal(t, []string{"database/creds/readonly/abc"}, revoked)
}

func TestMintRefusals(t *testing.T) {
	var revoked []string
	srv := vaultServer(t, vaultCreds(60), &revoked)
	good := fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, map[string]string{"vault_token": "root-token"})
	cases := []struct {
		name   string
		store  *store
		cfg    config.Config
		caller mint.CallerKind
		scope  map[string][]string
		em     audit.Emitter
		want   string
	}{
		{"agent", good, policyConfig(vaultPolicy()), mint.CallerAgent, nil, &recorder{}, "agent sessions"},
		{"no policy", good, config.Config{}, mint.CallerService, nil, &recorder{}, "no mint.vault policy"},
		{"human not allowed by default", good, policyConfig(vaultPolicy()), mint.CallerHuman, nil, &recorder{}, "not allowed"},
		{"other path", good, policyConfig(vaultPolicy()), mint.CallerService, map[string][]string{"path": {"secret/data/root"}}, &recorder{}, "not the policy's path"},
		{"foreign scope key", good, policyConfig(vaultPolicy()), mint.CallerService, map[string][]string{"scope": {"x"}}, &recorder{}, "does not apply"},
		{"no audit log", good, policyConfig(vaultPolicy()), mint.CallerService, nil, nil, "audit log"},
		{"missing token", fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, nil), policyConfig(vaultPolicy()), mint.CallerService, nil, &recorder{}, "no vault_token"},
		{"plain http address", fill(t, providermint.ProviderVault, map[string]string{"vault_addr": "http://vault.example.com"}, map[string]string{"vault_token": "root-token"}), policyConfig(vaultPolicy()), mint.CallerService, nil, &recorder{}, "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request(providermint.ProviderVault, tc.store, tc.cfg, tc.em)
			r.Caller, r.Scope = tc.caller, tc.scope
			_, err := providermint.Mint(context.Background(), r)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			if rec, ok := tc.em.(*recorder); ok {
				assert.Empty(t, rec.events, "a refusal before any mint is not a mint event")
			}
		})
	}
	var field *mintsession.FieldError
	_, err := providermint.Mint(context.Background(), request(providermint.ProviderVault, fill(t, providermint.ProviderVault, map[string]string{"vault_addr": srv.URL}, nil), policyConfig(vaultPolicy()), &recorder{}))
	require.ErrorAs(t, err, &field)
	assert.True(t, field.Missing)
	assert.Equal(t, "vault_token", field.Field)

	_, err = providermint.Mint(context.Background(), request("github-app", good, policyConfig(vaultPolicy()), &recorder{}))
	assert.ErrorIs(t, err, providermint.ErrUsage)
}

func serviceAccountKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	out, err := json.Marshal(map[string]string{"type": "service_account", "client_email": "source@p.iam.gserviceaccount.com", "private_key": string(pemKey), "token_uri": "https://evil.example/token"})
	require.NoError(t, err)
	return string(out)
}

type gcpStub struct {
	tokenForm   url.Values
	body        map[string]any
	expireAfter time.Duration
	iamAuth     string
	iamPath     string
	issuedScope string
}

func (g *gcpStub) servers(t *testing.T) providermint.Endpoints {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		g.tokenForm, _ = url.ParseQuery(string(raw))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "source-access", "expires_in": 3599})
	}))
	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokeninfo" {
			require.Equal(t, "impersonated", r.URL.Query().Get("access_token"))
			scopes := g.issuedScope
			if scopes == "" {
				for _, s := range g.body["scope"].([]any) {
					scopes += s.(string) + " "
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"scope": scopes, "exp": fmt.Sprint(time.Now().Add(g.expireAfter).Unix())})
			return
		}
		g.iamAuth, g.iamPath = r.Header.Get("Authorization"), r.URL.EscapedPath()
		_ = json.NewDecoder(r.Body).Decode(&g.body)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "impersonated", "expireTime": time.Now().Add(g.expireAfter).UTC().Format(time.RFC3339)})
	}))
	t.Cleanup(tokenSrv.Close)
	t.Cleanup(iamSrv.Close)
	return providermint.Endpoints{GCPToken: tokenSrv.URL, GCPIAM: iamSrv.URL, GCPTokenInfo: iamSrv.URL + "/tokeninfo"}
}

func gcpPolicy() config.MintPolicy {
	return config.MintPolicy{GCP: &config.GCPMintPolicy{
		ServiceAccount: "target@p.iam.gserviceaccount.com", Scopes: []string{"https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/bigquery"},
	}}
}

func TestGCPMint(t *testing.T) {
	g := &gcpStub{expireAfter: time.Hour}
	st := fill(t, providermint.ProviderGCP, nil, map[string]string{"service_account_key": serviceAccountKey(t)})
	r := request(providermint.ProviderGCP, st, policyConfig(gcpPolicy()), &recorder{})
	r.Endpoints = g.servers(t)

	s, err := providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	tok, _ := s.Value("access_token")
	assert.Equal(t, "impersonated", string(tok))
	assert.Equal(t, "Bearer source-access", g.iamAuth)
	assert.Contains(t, g.iamPath, "target@p.iam.gserviceaccount.com:generateAccessToken")
	assert.Equal(t, []any{"https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/bigquery"}, g.body["scope"])
	assert.Equal(t, "3600s", g.body["lifetime"])
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", g.tokenForm.Get("grant_type"))
	assert.Equal(t, 3, strings.Count(g.tokenForm.Get("assertion"), ".")+1)
	require.NoError(t, s.Close())

	t.Run("a request may narrow the scopes", func(t *testing.T) {
		r.Scope = map[string][]string{"scope": {"https://www.googleapis.com/auth/bigquery"}}
		s, err := providermint.Mint(context.Background(), r)
		require.NoError(t, err)
		assert.Equal(t, []any{"https://www.googleapis.com/auth/bigquery"}, g.body["scope"])
		assert.Equal(t, map[string][]string{"scope": {"https://www.googleapis.com/auth/bigquery"}}, s.Scope)
	})
	t.Run("a request may not widen them", func(t *testing.T) {
		r.Scope = map[string][]string{"scope": {"https://www.googleapis.com/auth/cloud-platform"}}
		_, err := providermint.Mint(context.Background(), r)
		assert.ErrorIs(t, err, mint.ErrDenied)
	})
	t.Run("a token that outlives the request is refused", func(t *testing.T) {
		g.expireAfter = 5 * time.Hour
		r.Scope = nil
		em := &recorder{}
		r.Audit = em
		_, err := providermint.Mint(context.Background(), r)
		require.Error(t, err)
		assert.Equal(t, []string{"error:scope_mismatch"}, em.reasons())
	})
}

func TestGCPMintRejectsBadKey(t *testing.T) {
	g := &gcpStub{expireAfter: time.Hour}
	for name, key := range map[string]string{
		"not json":     "nope",
		"wrong type":   `{"type":"authorized_user","client_email":"a@b"}`,
		"no RSA key":   `{"type":"service_account","client_email":"a@b","private_key":"x"}`,
		"empty secret": " ",
	} {
		t.Run(name, func(t *testing.T) {
			r := request(providermint.ProviderGCP, fill(t, providermint.ProviderGCP, nil, map[string]string{"service_account_key": key}), policyConfig(gcpPolicy()), &recorder{})
			r.Endpoints = g.servers(t)
			_, err := providermint.Mint(context.Background(), r)
			require.Error(t, err)
		})
	}
}

func jwtFor(aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]string{"aud": aud})
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(claims) + ".sig"
}

func azureServer(t *testing.T, aud string, expiresIn int, form *url.Values) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*form, _ = url.ParseQuery(string(raw))
		assert.Equal(t, "/tenant-1/oauth2/v2.0/token", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwtFor(aud), "expires_in": expiresIn})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func azureStore(t *testing.T) *store {
	return fill(t, providermint.ProviderAzure, map[string]string{"tenant_id": "tenant-1", "client_id": "client-1"}, map[string]string{"client_secret": "shh"})
}

func azurePolicy(ttl int) config.MintPolicy {
	return config.MintPolicy{Azure: &config.AzureMintPolicy{Resource: "api://vault-reader", MaxTTL: ttl}}
}

func TestAzureMint(t *testing.T) {
	var form url.Values
	r := request(providermint.ProviderAzure, azureStore(t), policyConfig(azurePolicy(0)), &recorder{})
	r.Endpoints.AzureAuthority = azureServer(t, "api://vault-reader", 3599, &form)
	s, err := providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "api://vault-reader/.default", form.Get("scope"))
	assert.Equal(t, "client-1", form.Get("client_id"))
	assert.Equal(t, map[string][]string{"resource": {"api://vault-reader"}}, s.Scope)
	require.NoError(t, s.Close())
}

func TestAzureFederatedMint(t *testing.T) {
	var form url.Values
	policy := azurePolicy(0)
	policy.Azure.Authentication = "federated"
	st := fill(t, providermint.ProviderAzure, map[string]string{"tenant_id": "tenant-1", "client_id": "client-1"}, map[string]string{"client_assertion": "external-issuer-jwt", "client_secret": "must-not-send"})
	r := request(providermint.ProviderAzure, st, policyConfig(policy), &recorder{})
	r.Endpoints.AzureAuthority = azureServer(t, "api://vault-reader", 3599, &form)
	secret, err := providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	defer secret.Close()
	assert.Equal(t, "external-issuer-jwt", form.Get("client_assertion"))
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.Get("client_assertion_type"))
	assert.NotContains(t, form, "client_secret")
	assert.Equal(t, "api://vault-reader/.default", form.Get("scope"))
	delete(st.m, connections.SecretFieldPath(ns, tmpl(providermint.ProviderAzure).Category, conn, "client_assertion"))
	_, err = providermint.Mint(context.Background(), r)
	require.Error(t, err, "missing assertion must not fall back to the client secret")
	r.Scope = map[string][]string{"resource": {"api://admin"}}
	_, err = providermint.Mint(context.Background(), r)
	require.ErrorIs(t, err, mint.ErrDenied)
}

func TestAzureMintFailsClosed(t *testing.T) {
	var form url.Values
	overflowSeconds := ^uint64(0)/uint64(time.Second) + 1
	cases := []struct {
		name      string
		aud       string
		expiresIn int
		ttl       int
		scope     map[string][]string
		want      string
	}{
		{"audience for another resource", "api://other", 3599, 0, nil, "audience"},
		{"token lives 90 minutes under the default limit", "api://vault-reader", 5400, 0, nil, "longer than"},
		{"token lifetime overflow", "api://vault-reader", int(overflowSeconds), 0, nil, "longer than"},
		{"token lives 90 minutes when the policy allows it", "api://vault-reader", 5400, 5400, nil, ""},
		{"another resource requested", "api://vault-reader", 3599, 0, map[string][]string{"resource": {"api://other"}}, "not the policy's resource"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request(providermint.ProviderAzure, azureStore(t), policyConfig(azurePolicy(tc.ttl)), &recorder{})
			r.Endpoints.AzureAuthority = azureServer(t, tc.aud, tc.expiresIn, &form)
			r.Scope = tc.scope
			_, err := providermint.Mint(context.Background(), r)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func oauthServer(t *testing.T, reply map[string]any, form *url.Values) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*form, _ = url.ParseQuery(string(raw))
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func oauthStore(t *testing.T) *store {
	return fill(t, providermint.ProviderOAuth, map[string]string{"client_id": "client-1"}, map[string]string{"client_secret": "shh", "refresh_token": "rt-1"})
}

func oauthPolicy(endpoint string, ttl int) config.MintPolicy {
	return config.MintPolicy{OAuth: &config.OAuthMintPolicy{TokenEndpoint: endpoint, Scopes: []string{"drive.readonly", "calendar.readonly"}, MaxTTL: ttl}}
}

func TestOAuthMint(t *testing.T) {
	var form url.Values
	endpoint := oauthServer(t, map[string]any{"access_token": "at-1", "expires_in": 3599, "scope": "drive.readonly"}, &form)
	r := request(providermint.ProviderOAuth, oauthStore(t), policyConfig(oauthPolicy(endpoint, 0)), &recorder{})
	r.Scope = map[string][]string{"scope": {"drive.readonly"}}
	s, err := providermint.Mint(context.Background(), r)
	require.NoError(t, err)
	tok, _ := s.Value("access_token")
	assert.Equal(t, "at-1", string(tok))
	assert.Equal(t, "refresh_token", form.Get("grant_type"))
	assert.Equal(t, "rt-1", form.Get("refresh_token"))
	assert.Equal(t, "drive.readonly", form.Get("scope"))
	require.NoError(t, s.Close())
}

func TestOAuthMintFailsClosed(t *testing.T) {
	var form url.Values
	cases := []struct {
		name  string
		reply map[string]any
		ttl   int
		scope map[string][]string
		want  string
	}{
		{"wider scope issued", map[string]any{"access_token": "at", "expires_in": 60, "scope": "drive.readonly contacts"}, 0, nil, "scope does not match"},
		{"no scope reported", map[string]any{"access_token": "at", "expires_in": 60}, 0, nil, "scope does not match"},
		{"lives too long", map[string]any{"access_token": "at", "expires_in": 5400, "scope": "drive.readonly calendar.readonly"}, 0, nil, "longer than"},
		{"scope outside the policy", map[string]any{"access_token": "at", "expires_in": 60, "scope": "x"}, 0, map[string][]string{"scope": {"contacts"}}, "not in the policy"},
		{"no access token", map[string]any{"expires_in": 60, "scope": "drive.readonly calendar.readonly"}, 0, nil, "missing access_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := oauthServer(t, tc.reply, &form)
			r := request(providermint.ProviderOAuth, oauthStore(t), policyConfig(oauthPolicy(endpoint, tc.ttl)), &recorder{})
			r.Scope = tc.scope
			_, err := providermint.Mint(context.Background(), r)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
	t.Run("insecure endpoint is refused before any key is read", func(t *testing.T) {
		r := request(providermint.ProviderOAuth, &store{m: map[string]string{}}, policyConfig(oauthPolicy("http://idp.example.com/token", 0)), &recorder{})
		_, err := providermint.Mint(context.Background(), r)
		require.ErrorIs(t, err, mint.ErrInvalidProviderPolicy)
	})
}

func TestParseScope(t *testing.T) {
	got, err := providermint.ParseScope(providermint.ProviderGCP, []string{"scope=a", "scope=b"})
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"scope": {"a", "b"}}, got)

	got, err = providermint.ParseScope(providermint.ProviderVault, nil)
	require.NoError(t, err)
	assert.Empty(t, got)

	for _, tc := range []struct {
		provider string
		pairs    []string
	}{
		{providermint.ProviderVault, []string{"path"}},
		{providermint.ProviderVault, []string{"path="}},
		{providermint.ProviderVault, []string{"repo=a/b"}},
		{providermint.ProviderVault, []string{"path=a", "path=b"}},
		{providermint.ProviderAzure, []string{"resource=a", "resource=b"}},
	} {
		_, err := providermint.ParseScope(tc.provider, tc.pairs)
		assert.ErrorIs(t, err, providermint.ErrUsage, "%v", tc)
	}
	assert.Nil(t, providermint.ScopeKeys("github-app"))
	assert.False(t, providermint.Supports("github-app"))
}
