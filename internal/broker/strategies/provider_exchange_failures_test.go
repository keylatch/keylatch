package strategies

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

type scRT func(*http.Request) (*http.Response, error)

func (f scRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type scBrokenBody struct{}

func (scBrokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (scBrokenBody) Close() error             { return nil }

// scRedirect sends every request to srv regardless of the original host.
func scRedirect(srv *httptest.Server) *http.Client {
	target, _ := url.Parse(srv.URL)
	return &http.Client{Transport: scRT(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

func scBrokenClient() *http.Client {
	return &http.Client{Transport: scRT(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: scBrokenBody{}}, nil
	})}
}

func scDeadClient() *http.Client {
	return &http.Client{Transport: scRT(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial refused")
	})}
}

func scJSONServer(t *testing.T, status int, body string, inspect func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inspect != nil {
			inspect(r)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func scRefresh(tok string) func(string, string) ([]byte, error) {
	return func(string, string) ([]byte, error) { return []byte(tok), nil }
}

func scFakeToken(prefix string) string { return prefix + strings.Repeat("q", 24) }

func TestDropbox_RefreshFlow(t *testing.T) {
	refresh := scFakeToken("refresh-")
	access := scFakeToken("access-")
	var form url.Values
	srv := scJSONServer(t, http.StatusOK, `{"access_token":"`+access+`"}`, func(r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
	})
	s := NewDropboxOAuthStrategy("cid", "csecret", scRefresh(refresh))
	s.httpClient = scRedirect(srv)
	if s.Provider() != "dropbox" {
		t.Fatalf("provider = %q", s.Provider())
	}

	res, err := s.Exchange(context.Background(), "actor", "sess", "default")
	if err != nil {
		t.Fatal(err)
	}
	if string(res.TokenBytes()) != access {
		t.Fatal("access token not carried in result")
	}
	if res.TTLRemaining != dropboxDefaultTTL {
		t.Fatalf("TTL = %v, want default %v", res.TTLRemaining, dropboxDefaultTTL)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != refresh || form.Get("client_id") != "cid" {
		t.Fatalf("form = %v", form)
	}
	if res.Provider != "dropbox" || res.ExchangeType != broker.FreshExchange {
		t.Fatalf("result meta = %+v", res)
	}
}

func TestDropbox_ResponseHandling(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
		wantSub string
		wantTTL time.Duration
	}{
		{"expires_in honoured", 200, `{"access_token":"a-tok","expires_in":120}`, nil, "", 2 * time.Minute},
		{"invalid_grant", 400, `{"error":"invalid_grant"}`, broker.ErrExpiredRefreshToken, "", 0},
		{"invalid_token", 401, `{"error":"invalid_token"}`, broker.ErrExpiredRefreshToken, "", 0},
		{"server error", 500, `{"error":"other"}`, nil, "server returned 500", 0},
		{"missing token", 200, `{"token_type":"bearer"}`, nil, "missing access_token", 0},
		{"not json", 200, `<html>`, nil, "parse response", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewDropboxOAuthStrategy("cid", "cs", scRefresh("r"))
			s.httpClient = scRedirect(scJSONServer(t, tc.status, tc.body, nil))
			res, err := s.Exchange(context.Background(), "a", "s", "n")
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
			case tc.wantSub != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("want %q, got %v", tc.wantSub, err)
				}
			default:
				if err != nil || res.TTLRemaining != tc.wantTTL {
					t.Fatalf("ttl=%v err=%v", res.TTLRemaining, err)
				}
			}
		})
	}
}

func TestDropbox_TransportAndSourceFailures(t *testing.T) {
	s := NewDropboxOAuthStrategy("cid", "cs", func(string, string) ([]byte, error) { return nil, errors.New("locked") })
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "get refresh token") {
		t.Fatalf("source error: %v", err)
	}
	s = NewDropboxOAuthStrategy("cid", "cs", scRefresh("r"))
	s.httpClient = scDeadClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "http request") {
		t.Fatalf("transport error: %v", err)
	}
	s.httpClient = scBrokenClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read error: %v", err)
	}
}

func TestGoogleAndMicrosoft_EndpointsAndExchange(t *testing.T) {
	g := NewGoogleOAuthStrategy("cid", "cs", scRefresh("r"))
	if g.Provider() != "google" || g.tokenEndpoint != googleTokenEndpoint {
		t.Fatalf("google: %q %q", g.Provider(), g.tokenEndpoint)
	}
	m := NewMicrosoftOAuthStrategy("tenant-1", "cid", "cs", scRefresh("r"))
	if m.Provider() != "microsoft" || m.tokenEndpoint != "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token" {
		t.Fatalf("microsoft: %q %q", m.Provider(), m.tokenEndpoint)
	}
	var hostSeen string
	srv := scJSONServer(t, 200, `{"access_token":"tok-abc","expires_in":60}`, nil)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: scRT(func(r *http.Request) (*http.Response, error) {
		hostSeen = r.URL.Host
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
	m.httpClient = client
	res, err := m.Exchange(context.Background(), "a", "s", "n")
	if err != nil || string(res.TokenBytes()) != "tok-abc" || res.TTLRemaining != time.Minute {
		t.Fatalf("microsoft exchange: %+v %v", res, err)
	}
	if hostSeen != "login.microsoftonline.com" {
		t.Fatalf("request host = %q", hostSeen)
	}
}

func TestOAuthRefresh_RequestFailures(t *testing.T) {
	s := NewOAuthRefreshStrategy("p", "://bad-endpoint", "cid", "cs", scRefresh("r"))
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("build: %v", err)
	}
	s = NewOAuthRefreshStrategy("p", "https://idp.example.test/token", "cid", "cs", scRefresh("r"))
	s.httpClient = scDeadClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "http request") {
		t.Fatalf("transport: %v", err)
	}
	s.httpClient = scBrokenClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read: %v", err)
	}
	s.httpClient = scRedirect(scJSONServer(t, 200, "not-json", nil))
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("parse: %v", err)
	}
}

func TestSlackToken_Exchange(t *testing.T) {
	tok := scFakeToken("slack-test-")
	s := NewSlackTokenStrategy(func(actor, ns string) ([]byte, error) {
		if actor != "bot" || ns != "team" {
			return nil, errors.New("unexpected lookup")
		}
		return []byte(tok), nil
	})
	if s.Provider() != "slack" {
		t.Fatalf("provider = %q", s.Provider())
	}
	res, err := s.Exchange(context.Background(), "bot", "sess", "team")
	if err != nil {
		t.Fatal(err)
	}
	if string(res.TokenBytes()) != tok || res.TTLRemaining != time.Duration(math.MaxInt64) {
		t.Fatalf("result = %+v", res)
	}
	res.Zero()
	if string(res.TokenBytes()) == tok {
		t.Fatal("Zero did not clear token bytes")
	}

	empty := NewSlackTokenStrategy(func(string, string) ([]byte, error) { return nil, nil })
	if _, err := empty.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("empty: %v", err)
	}
	failing := NewSlackTokenStrategy(func(string, string) ([]byte, error) { return nil, errors.New("keyring locked") })
	if _, err := failing.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "get from keyring") {
		t.Fatalf("source: %v", err)
	}
}

func TestVaultDynamic_ExchangeEdges(t *testing.T) {
	vtok := scFakeToken("vault-test-")
	var gotToken, gotPath string
	srv := scJSONServer(t, 200, `{"lease_id":"lease/1","lease_duration":0,"data":{"username":"u"}}`, func(r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		gotPath = r.URL.Path
	})
	s := NewVaultDynamicSecretStrategy(srv.URL, "database/creds/ro", func(string) ([]byte, error) { return []byte(vtok), nil })
	if s.Provider() != "hashicorp-vault" {
		t.Fatalf("provider = %q", s.Provider())
	}
	res, err := s.Exchange(context.Background(), "a", "s", "n")
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != vtok || gotPath != "/v1/database/creds/ro" {
		t.Fatalf("request token/path = %q %q", gotToken, gotPath)
	}
	if res.TTLRemaining != time.Hour {
		t.Fatalf("default TTL = %v", res.TTLRemaining)
	}
	var data map[string]any
	if err := json.Unmarshal(res.TokenBytes(), &data); err != nil || data["lease_id"] != "lease/1" {
		t.Fatalf("token data = %s %v", res.TokenBytes(), err)
	}

	bad := NewVaultDynamicSecretStrategy("://bad", "p", func(string) ([]byte, error) { return []byte("t"), nil })
	if _, err := bad.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("build: %v", err)
	}
	s.httpClient = scDeadClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "http request") {
		t.Fatalf("transport: %v", err)
	}
	s.httpClient = scBrokenClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read: %v", err)
	}
	s.httpClient = scRedirect(scJSONServer(t, 200, "{", nil))
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("parse: %v", err)
	}
}

func TestVaultDynamic_RevokeLeaseOutcomes(t *testing.T) {
	var body string
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, method = string(b), r.Method
		if strings.Contains(body, "deny") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	s := NewVaultDynamicSecretStrategy(srv.URL, "p", nil)

	if err := s.RevokeLease(context.Background(), "lease/ok", []byte("t")); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || body != `{"lease_id":"lease/ok"}` {
		t.Fatalf("revoke request = %s %s", method, body)
	}
	if err := s.RevokeLease(context.Background(), "deny", []byte("t")); err == nil || !strings.Contains(err.Error(), "revoke returned 403") {
		t.Fatalf("status: %v", err)
	}
	s.httpClient = scDeadClient()
	if err := s.RevokeLease(context.Background(), "x", []byte("t")); err == nil || !strings.Contains(err.Error(), "revoke http request") {
		t.Fatalf("transport: %v", err)
	}
	bad := NewVaultDynamicSecretStrategy("://bad", "p", nil)
	if err := bad.RevokeLease(context.Background(), "x", []byte("t")); err == nil || !strings.Contains(err.Error(), "revoke build request") {
		t.Fatalf("build: %v", err)
	}
}

func TestAWSSts_SigningAndResponseEdges(t *testing.T) {
	var q url.Values
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		auth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>id</AccessKeyId><SecretAccessKey>sk</SecretAccessKey><SessionToken>st</SessionToken><Expiration>not-a-time</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(srv.Close)

	creds := func(string) (string, string, error) { return "test-access-id", "test-secret", nil }
	s := NewAWSStsStrategyWithEndpoint("arn:aws:iam::123456789012:role/r", "eu-west-1", creds, srv.URL)
	session := strings.Repeat("sess ion/", 20)
	res, err := s.Exchange(context.Background(), "a", session, "n")
	if err != nil {
		t.Fatal(err)
	}
	name := q.Get("RoleSessionName")
	if len(name) != 64 || strings.ContainsAny(name, " /") {
		t.Fatalf("RoleSessionName = %q (len %d)", name, len(name))
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=test-access-id/") || !strings.Contains(auth, "/eu-west-1/sts/aws4_request") {
		t.Fatalf("Authorization = %q", auth)
	}
	if strings.Contains(auth, "test-secret") {
		t.Fatal("secret key sent in Authorization header")
	}
	if res.TTLRemaining != time.Hour {
		t.Fatalf("TTL with unparsable expiration = %v", res.TTLRemaining)
	}

	bad := NewAWSStsStrategyWithEndpoint("arn", "us-east-1", creds, "://bad")
	if _, err := bad.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("build: %v", err)
	}
	s.httpClient = scDeadClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "http request") {
		t.Fatalf("transport: %v", err)
	}
	s.httpClient = scBrokenClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read: %v", err)
	}
	s.httpClient = scRedirect(scJSONServer(t, 200, "<unclosed", nil))
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "parse XML") {
		t.Fatalf("parse: %v", err)
	}
}

func TestGitHubApp_JWTAndResponseEdges(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var authz string
	expires := time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/app/installations/revoked/access_tokens":
			w.WriteHeader(http.StatusUnauthorized)
		case "/app/installations/garbage/access_tokens":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, "{")
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"token":"inst-tok","expires_at":"`+expires+`"}`)
		}
	}))
	t.Cleanup(srv.Close)

	s := NewGitHubAppInstallationStrategy("4242", "ok", key, WithGitHubAPIBase(srv.URL))
	res, err := s.Exchange(context.Background(), "a", "s", "n")
	if err != nil {
		t.Fatal(err)
	}
	if res.TTLRemaining <= 25*time.Minute || res.TTLRemaining > 30*time.Minute {
		t.Fatalf("TTL from expires_at = %v", res.TTLRemaining)
	}

	jwtStr := strings.TrimPrefix(authz, "Bearer ")
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("app JWT has %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("app JWT signature invalid: %v", err)
	}
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil || claims.Iss != "4242" || claims.Exp-claims.Iat > 600 {
		t.Fatalf("claims = %+v %v", claims, err)
	}

	revoked := NewGitHubAppInstallationStrategy("4242", "revoked", key, WithGitHubAPIBase(srv.URL))
	if _, err := revoked.Exchange(context.Background(), "a", "s", "n"); !errors.Is(err, broker.ErrRevokedSession) {
		t.Fatalf("401: %v", err)
	}
	garbage := NewGitHubAppInstallationStrategy("4242", "garbage", key, WithGitHubAPIBase(srv.URL))
	if _, err := garbage.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("parse: %v", err)
	}
	badURL := NewGitHubAppInstallationStrategy("4242", "x", key, WithGitHubAPIBase("://bad"))
	if _, err := badURL.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("build: %v", err)
	}
	s.httpClient = scDeadClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "http request") {
		t.Fatalf("transport: %v", err)
	}
	s.httpClient = scBrokenClient()
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("read: %v", err)
	}
}

func TestCustomTemplate_RevalidatesOutputFieldsAtExchange(t *testing.T) {
	called := false
	s, err := NewCustomTemplateStrategy("p", []string{"username"}, func(context.Context, string, string, string) ([]byte, time.Duration, error) {
		called = true
		return []byte("v"), time.Minute, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.outputFields = append(s.outputFields, " Secret ")
	if _, err := s.Exchange(context.Background(), "a", "s", "n"); err == nil || !strings.Contains(err.Error(), "template validation failed") {
		t.Fatalf("want validation failure, got %v", err)
	}
	if called {
		t.Fatal("exchange func ran despite forbidden output field")
	}
}
