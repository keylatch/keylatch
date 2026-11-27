package cloudcreds

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/providermint"
)

type events struct {
	mu   sync.Mutex
	fail bool
	list []audit.Event
}

func (e *events) Emit(_ context.Context, event audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail {
		return errors.New("audit unavailable")
	}
	e.list = append(e.list, event)
	return nil
}

func testConfig(provider string) Config {
	c := Config{Provider: provider, Connection: provider, Account: "app@project.iam.gserviceaccount.com", Scopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}, Resource: "https://management.azure.com/", Audit: &events{}}
	scope := map[string][]string{"scope": c.Scopes}
	if provider == "azure" {
		scope = map[string][]string{"resource": {c.Resource}}
	}
	c.Initial = &providermint.Secret{Fields: map[string][]byte{"access_token": []byte("minted-cloud-access-token")}, ExpiresAt: time.Now().Add(5 * time.Minute), Scope: scope}
	return c
}

func start(t *testing.T, provider string) *Server {
	t.Helper()
	s, err := Start(context.Background(), testConfig(provider))
	require.NoError(t, err)
	t.Cleanup(s.Close)
	return s
}

func TestOfficialGoogleSDK(t *testing.T) {
	s := start(t, "gcp")
	t.Setenv("GCE_METADATA_HOST", s.MetadataHost())
	client := metadata.NewClient(&http.Client{Timeout: 5 * time.Second})
	email, err := client.EmailWithContext(context.Background(), "default")
	require.NoError(t, err)
	assert.Equal(t, s.cfg.Account, email)
	project, err := client.ProjectIDWithContext(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "project", project)
	token, err := google.ComputeTokenSource("default", s.cfg.Scopes...).Token()
	require.NoError(t, err)
	assert.Equal(t, "minted-cloud-access-token", token.AccessToken)
	assert.WithinDuration(t, s.cfg.Initial.ExpiresAt, token.Expiry, 2*time.Second)
	assert.NotContains(t, s.MetadataHost(), token.AccessToken)
}

func TestOfficialAzureSDK(t *testing.T) {
	s := start(t, "azure")
	for _, name := range []string{"MSI_ENDPOINT", "MSI_SECRET", "IMDS_ENDPOINT", "IDENTITY_SERVER_THUMBPRINT"} {
		t.Setenv(name, "")
	}
	t.Setenv("IDENTITY_ENDPOINT", s.IdentityEndpoint())
	t.Setenv("IDENTITY_HEADER", s.IdentityHeader())
	credential, err := azidentity.NewManagedIdentityCredential(nil)
	require.NoError(t, err)
	token, err := credential.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{strings.TrimRight(s.cfg.Resource, "/") + "/.default"}})
	require.NoError(t, err)
	assert.Equal(t, "minted-cloud-access-token", token.Token)
	assert.WithinDuration(t, s.cfg.Initial.ExpiresAt, token.ExpiresOn, time.Second)
	assert.NotContains(t, s.IdentityEndpoint()+s.IdentityHeader(), token.Token)
}

func TestGCPMetadataAndRefusals(t *testing.T) {
	s := start(t, "gcp")
	for _, tc := range []struct {
		path string
		code int
	}{
		{"instance/service-accounts/", 200},
		{"instance/service-accounts/default/scopes", 200},
		{"instance/service-accounts/default/?recursive=true", 200},
		{"instance/service-accounts/default/token", 200},
		{"instance/service-accounts/default/token?scopes=unapproved", 403},
		{"instance/service-accounts/default/token?scopes=a&scopes=b", 403},
		{"instance/service-accounts/default/token?unknown=x", 403},
		{"instance/service-accounts/default/token?scopes=%zz", 400},
		{"instance/service-accounts/default/email?unknown=x", 400},
		{"instance/service-accounts/other/token", 404},
	} {
		r := httptest.NewRequest("GET", s.base+"/computeMetadata/v1/"+tc.path, nil)
		r.Header.Set("Metadata-Flavor", "Google")
		w := httptest.NewRecorder()
		s.serve(w, r)
		assert.Equal(t, tc.code, w.Code, tc.path)
		if tc.code != 200 {
			assert.NotContains(t, w.Body.String(), "minted-cloud-access-token")
		}
	}
}

func TestAzureIMDSAndRefusals(t *testing.T) {
	s := start(t, "azure")
	base := s.IdentityEndpoint() + "?api-version=2018-02-01&resource=" + url.QueryEscape(s.cfg.Resource)
	for _, tc := range []struct {
		suffix, header, value string
		code                  int
	}{
		{"", "Metadata", "true", 200},
		{"", "X-IDENTITY-HEADER", s.IdentityHeader(), 200},
		{"", "X-IDENTITY-HEADER", "wrong", 403},
		{"", "", "", 403},
		{"&resource=other", "Metadata", "true", 400},
		{"&client_id=other", "Metadata", "true", 400},
		{"&x=%zz", "Metadata", "true", 400},
	} {
		r := httptest.NewRequest("GET", base+tc.suffix, nil)
		if tc.header != "" {
			r.Header.Set(tc.header, tc.value)
		}
		w := httptest.NewRecorder()
		s.serve(w, r)
		assert.Equal(t, tc.code, w.Code)
		if tc.code != 200 {
			assert.NotContains(t, w.Body.String(), "minted-cloud-access-token")
		}
	}
	for _, query := range []string{"api-version=2018-02-01&resource=other", "api-version=other&resource=" + url.QueryEscape(s.cfg.Resource)} {
		r := httptest.NewRequest("GET", s.IdentityEndpoint()+"?"+query, nil)
		r.Header.Set("Metadata", "true")
		w := httptest.NewRecorder()
		s.serve(w, r)
		assert.NotEqual(t, 200, w.Code)
	}
}

func TestWrongHostPathMethodAndForwardingDenied(t *testing.T) {
	for _, provider := range []string{"gcp", "azure"} {
		s := start(t, provider)
		for _, kind := range []string{"host", "path", "method", "forwarded", "xff", "google_header"} {
			r := httptest.NewRequest("GET", s.base+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
			r.Header.Set("Metadata-Flavor", "Google")
			if provider == "azure" {
				r = httptest.NewRequest("GET", s.IdentityEndpoint()+"?api-version=2018-02-01&resource="+url.QueryEscape(s.cfg.Resource), nil)
				r.Header.Set("Metadata", "true")
			}
			switch kind {
			case "host":
				r.Host = "evil.example"
			case "path":
				r.URL.Path = "/unknown"
			case "method":
				r.Method = "POST"
			case "forwarded":
				r.Header.Set("Forwarded", "for=external")
			case "xff":
				r.Header.Set("X-Forwarded-For", "external")
			case "google_header":
				r.Header.Del("Metadata-Flavor")
				r.Header.Del("Metadata")
			}
			w := httptest.NewRecorder()
			s.serve(w, r)
			assert.Equal(t, 403, w.Code, provider+"/"+kind)
		}
	}
}

func TestAuditFailureDoesNotReleaseToken(t *testing.T) {
	s := start(t, "gcp")
	e := s.cfg.Audit.(*events)
	e.mu.Lock()
	e.fail = true
	e.mu.Unlock()
	r := httptest.NewRequest("GET", s.base+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	r.Header.Set("Metadata-Flavor", "Google")
	w := httptest.NewRecorder()
	s.serve(w, r)
	assert.Equal(t, 503, w.Code)
	assert.NotContains(t, w.Body.String(), "minted-cloud-access-token")
}

func TestExpiryAndCancellationCloseAndWipe(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		cfg := testConfig("gcp")
		if expiry {
			cfg.Initial.ExpiresAt = time.Now().Add(30 * time.Millisecond)
		}
		value := cfg.Initial.Fields["access_token"]
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s, err := Start(ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(s.Close)
		if !expiry {
			cancel()
		}
		require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }, 2*time.Second, 5*time.Millisecond)
		s.Close()
		assert.Equal(t, make([]byte, len(value)), value)
		_, _, err = s.credential(context.Background())
		assert.Error(t, err)
		response, err := http.Get(s.base)
		if response != nil {
			_ = response.Body.Close()
		}
		assert.Error(t, err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Provider = "other" }, func(c *Config) { c.Initial = nil }, func(c *Config) { c.Audit = nil },
		func(c *Config) { c.Account = "" }, func(c *Config) { c.Scopes = nil }, func(c *Config) { c.Provider = "azure"; c.Resource = "" },
		func(c *Config) { c.Initial.ExpiresAt = time.Now().Add(-time.Second) }, func(c *Config) { c.Initial.ExpiresAt = time.Now().Add(2 * time.Hour) },
		func(c *Config) { c.Initial.Fields = nil }, func(c *Config) { c.Initial.Scope = map[string][]string{"scope": {"other"}} },
	} {
		cfg := testConfig("gcp")
		mutate(&cfg)
		s, err := Start(context.Background(), cfg)
		require.Error(t, err)
		assert.Nil(t, s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Start(ctx, testConfig("gcp"))
	assert.Error(t, err)
}

func TestTokenResponseIsAuditedAndNotCached(t *testing.T) {
	s := start(t, "gcp")
	r, err := http.NewRequest("GET", s.base+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	require.NoError(t, err)
	r.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(r)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	var token map[string]any
	require.NoError(t, json.Unmarshal(body, &token))
	assert.Equal(t, "Bearer", token["token_type"])
	e := s.cfg.Audit.(*events)
	e.mu.Lock()
	defer e.mu.Unlock()
	require.Len(t, e.list, 1)
	encoded, err := json.Marshal(e.list)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "minted-cloud-access-token")
	assert.NotContains(t, string(encoded), s.token)
}
