package strategies_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func oauthStub(t *testing.T, reply map[string]any, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func refreshToken(string, string) ([]byte, error) { return []byte("rt"), nil }

func TestOAuthMintScopedLifetime(t *testing.T) {
	ok := map[string]any{"access_token": "at", "expires_in": 3000, "scope": "a b"}
	s := strategies.NewOAuthRefreshStrategy("p", oauthStub(t, ok, 200), "id", "secret", refreshToken, strategies.WithScopes("a", "b"))
	tok, err := s.MintScoped(context.Background(), "actor", "ns", 0)
	require.NoError(t, err)
	assert.Equal(t, "at", string(tok.AccessToken))
	assert.Equal(t, []string{"a", "b"}, tok.Scopes)
	assert.WithinDuration(t, time.Now().Add(3000*time.Second), tok.ExpiresAt, time.Minute)
	tok.Zero()
	assert.Equal(t, []byte{0, 0}, tok.AccessToken)

	long := map[string]any{"access_token": "at", "expires_in": 7200, "scope": "a"}
	s = strategies.NewOAuthRefreshStrategy("p", oauthStub(t, long, 200), "id", "secret", refreshToken, strategies.WithScopes("a"))
	_, err = s.MintScoped(context.Background(), "actor", "ns", time.Hour)
	require.ErrorIs(t, err, strategies.ErrOAuthScopeMismatch)
	_, err = s.MintScoped(context.Background(), "actor", "ns", 3*time.Hour)
	require.NoError(t, err, "a caller that opts in to a longer lifetime gets it")

	res, err := s.Exchange(context.Background(), "actor", "sess", "ns")
	require.NoError(t, err, "the broker path keeps the provider's lifetime")
	assert.Equal(t, "p", res.Provider)
}

func TestOAuthMintScopedFailures(t *testing.T) {
	revoked := oauthStub(t, map[string]any{"error": "invalid_grant"}, 400)
	_, err := strategies.NewOAuthRefreshStrategy("p", revoked, "id", "s", refreshToken).MintScoped(context.Background(), "a", "ns", 0)
	assert.ErrorIs(t, err, broker.ErrExpiredRefreshToken)

	_, err = strategies.NewOAuthRefreshStrategy("p", oauthStub(t, map[string]any{}, 500), "id", "s", refreshToken).MintScoped(context.Background(), "a", "ns", 0)
	assert.Error(t, err)

	failing := func(string, string) ([]byte, error) { return nil, errors.New("locked") }
	_, err = strategies.NewOAuthRefreshStrategy("p", "http://127.0.0.1:1", "id", "s", failing).MintScoped(context.Background(), "a", "ns", 0)
	assert.ErrorContains(t, err, "locked")

	_, err = strategies.NewOAuthRefreshStrategy("p", "http://127.0.0.1:1", "id", "s", refreshToken,
		strategies.WithOAuthHTTPClient(&http.Client{Timeout: time.Second})).MintScoped(context.Background(), "a", "ns", 0)
	assert.Error(t, err)

	g := strategies.NewGoogleOAuthStrategy("id", "s", refreshToken)
	m := strategies.NewMicrosoftOAuthStrategy("common", "id", "s", refreshToken)
	assert.Equal(t, "google", g.Provider())
	assert.Equal(t, "microsoft", m.Provider())
}

func TestOAuthMintRejectsMissingBounds(t *testing.T) {
	for _, reply := range []map[string]any{
		{"access_token": "at", "scope": "a b"},
		{"access_token": "at", "scope": "a b", "expires_in": -1},
		{"access_token": "at", "scope": "a b", "expires_in": 0.5},
		{"access_token": "at", "scope": "a b", "expires_in": 1e30},
		{"access_token": "at", "scope": "a", "expires_in": 60},
	} {
		s := strategies.NewOAuthRefreshStrategy("p", oauthStub(t, reply, 200), "id", "secret", refreshToken, strategies.WithScopes("a", "b"))
		tok, err := s.MintScoped(context.Background(), "a", "ns", time.Hour)
		require.ErrorIs(t, err, strategies.ErrOAuthScopeMismatch)
		assert.Empty(t, tok.AccessToken)
	}
}

func TestMintClientsRefuseCredentialRedirects(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	secret := func(string) ([]byte, error) { return []byte("root-secret"), nil }
	_, err := strategies.NewOAuthRefreshStrategy("p", source.URL, "id", "secret", refreshToken, strategies.WithScopes("a")).MintScoped(context.Background(), "a", "ns", time.Hour)
	require.Error(t, err)
	_, err = strategies.NewAzureClientCredentialsStrategy("tenant", "client", secret, strategies.WithAzureAuthority(source.URL)).MintScoped(context.Background(), "ns", "resource")
	require.Error(t, err)
	_, err = strategies.NewVaultDynamicSecretStrategy(source.URL, "database/creds/read", secret).MintScoped(context.Background(), "ns", strategies.VaultScope{})
	require.Error(t, err)
	_, err = strategies.NewGCPImpersonationStrategy("account", secret, strategies.WithGCPEndpoint(source.URL)).MintScoped(context.Background(), "ns", strategies.GCPScope{Scopes: []string{"a"}})
	require.Error(t, err)
	assert.False(t, called, "credential-bearing requests must not follow redirects")
}

func TestGCPIntrospectionFailsClosed(t *testing.T) {
	issued := "private-minted-token"
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": issued, "expireTime": time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)})
	}))
	defer source.Close()
	for _, tc := range []struct {
		name, scope, expiry string
		status              int
	}{
		{"wider", "a b", fmt.Sprint(time.Now().Add(30 * time.Minute).Unix()), 200},
		{"narrower", "", "1", 200},
		{"invalid expiry", "a", "bad", 200},
		{"expired", "a", "1", 200},
		{"too long", "a", "99999999999", 200},
		{"unavailable", "a", "1", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, issued, r.URL.Query().Get("access_token"))
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"scope": tc.scope, "exp": tc.expiry})
			}))
			defer info.Close()
			s := strategies.NewGCPImpersonationStrategy("sa@p", func(string) ([]byte, error) { return []byte("source"), nil }, strategies.WithGCPEndpoint(source.URL), strategies.WithGCPTokenInfoURL(info.URL))
			tok, err := s.MintScoped(context.Background(), "ns", strategies.GCPScope{Scopes: []string{"a"}})
			require.ErrorIs(t, err, strategies.ErrGCPScopeMismatch)
			assert.Empty(t, tok.AccessToken)
			assert.False(t, strings.Contains(err.Error(), issued))
		})
	}
}

func TestAzureMaxLifetimeOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": jwtWithAudience("api://r"), "expires_in": 5400})
	}))
	t.Cleanup(srv.Close)
	secret := func(string) ([]byte, error) { return []byte("s"), nil }

	s := strategies.NewAzureClientCredentialsStrategy("t", "c", secret, strategies.WithAzureAuthority(srv.URL))
	_, err := s.MintScoped(context.Background(), "ns", "api://r")
	require.ErrorIs(t, err, strategies.ErrAzureScopeMismatch)

	s = strategies.NewAzureClientCredentialsStrategy("t", "c", secret, strategies.WithAzureAuthority(srv.URL), strategies.WithAzureMaxLifetime(90*time.Minute))
	tok, err := s.MintScoped(context.Background(), "ns", "api://r")
	require.NoError(t, err)
	tok.Zero()
	assert.Equal(t, "azure", s.Provider())

	_, err = s.MintScoped(context.Background(), "ns", "")
	assert.Error(t, err)
	failing := strategies.NewAzureClientCredentialsStrategy("t", "c", func(string) ([]byte, error) { return nil, errors.New("locked") })
	_, err = failing.MintScoped(context.Background(), "ns", "api://r")
	assert.ErrorContains(t, err, "locked")
}

func TestGCPSourceTokenFromKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	file, err := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "sa@p.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
	require.NoError(t, err)

	var form url.Values
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(raw))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "src"})
	}))
	t.Cleanup(srv.Close)

	tok, err := strategies.GCPSourceTokenFromKey(file, srv.URL, srv.Client())("ns")
	require.NoError(t, err)
	assert.Equal(t, "src", string(tok))
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", form.Get("grant_type"))

	status = http.StatusUnauthorized
	_, err = strategies.GCPSourceTokenFromKey(file, srv.URL, nil)("ns")
	assert.ErrorContains(t, err, "401")

	_, err = strategies.GCPSourceTokenFromKey([]byte("{}"), srv.URL, nil)("ns")
	assert.ErrorContains(t, err, "not a service account key")
	_, err = strategies.GCPSourceTokenFromKey([]byte(`{"type":"service_account","client_email":"a@b","private_key":"x"}`), srv.URL, nil)("ns")
	assert.ErrorContains(t, err, "RSA")
	_, err = strategies.GCPSourceTokenFromKey(file, "http://127.0.0.1:1", &http.Client{Timeout: time.Second})("ns")
	assert.Error(t, err)

	g := strategies.NewGCPImpersonationStrategy("sa@p", func(string) ([]byte, error) { return nil, errors.New("locked") })
	_, err = g.MintScoped(context.Background(), "ns", strategies.GCPScope{Scopes: []string{"s"}})
	assert.ErrorContains(t, err, "locked")
	assert.Equal(t, "gcp", g.Provider())
	_, err = g.MintScoped(context.Background(), "ns", strategies.GCPScope{})
	assert.Error(t, err)
	_, err = g.MintScoped(context.Background(), "ns", strategies.GCPScope{Scopes: []string{"s"}, Lifetime: 2 * time.Hour})
	assert.Error(t, err)
	tokenZero := strategies.GCPToken{AccessToken: []byte("x")}
	tokenZero.Zero()
	assert.Equal(t, []byte{0}, tokenZero.AccessToken)
}

func TestVaultRevokeFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(srv.Close)
	s := strategies.NewVaultDynamicSecretStrategy(srv.URL, "/a/b", func(string) ([]byte, error) { return []byte("t"), nil })
	assert.Equal(t, "hashicorp-vault", s.Provider())
	assert.ErrorContains(t, s.Revoke(context.Background(), "ns", "lease"), "403")
	_, err := s.MintScoped(context.Background(), "ns", strategies.VaultScope{})
	assert.ErrorContains(t, err, "403")

	locked := strategies.NewVaultDynamicSecretStrategy(srv.URL, "a", func(string) ([]byte, error) { return nil, errors.New("locked") })
	assert.ErrorContains(t, locked.Revoke(context.Background(), "ns", "l"), "locked")
	_, err = locked.MintScoped(context.Background(), "ns", strategies.VaultScope{})
	assert.ErrorContains(t, err, "locked")

	lease := strategies.VaultLease{LeaseID: "x", Data: map[string]any{"a": 1}}
	lease.Zero()
	assert.Empty(t, lease.LeaseID)
}
