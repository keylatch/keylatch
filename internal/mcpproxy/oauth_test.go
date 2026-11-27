package mcpproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/mcpproxy"
)

// Built by concatenation so scanners do not flag the fixtures.
const (
	refreshCredential = "refresh" + "-credential-0123456789abcdef"
	clientSecret      = "client" + "-secret-0123456789abcdef"
	accessOne         = "access" + "-token-one-0123456789abcdef"
	accessTwo         = "access" + "-token-two-0123456789abcdef"
	rotatedRefresh    = "refresh" + "-rotated-0123456789abcdef"
)

const ping = `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"

// authServer is an OAuth authorization server that records the forms posted to
// its token endpoint.
type authServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	forms []url.Values
}

func newAuthServer(t *testing.T, token func(w http.ResponseWriter, form url.Values, n int)) *authServer {
	t.Helper()
	as := &authServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		as.mu.Lock()
		as.forms = append(as.forms, r.PostForm)
		n := len(as.forms)
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		token(w, r.PostForm, n)
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func (a *authServer) calls() []url.Values {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]url.Values(nil), a.forms...)
}

func issue(access string, expiresIn int) func(http.ResponseWriter, url.Values, int) {
	return func(w http.ResponseWriter, _ url.Values, _ int) {
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":%d}`, access, expiresIn)
	}
}

// oauthFixture is a remote MCP server whose slot is bound to the authorization
// server as well.
func oauthFixture(t *testing.T, as *authServer, grant, credential string, handle func(http.ResponseWriter, *http.Request, []byte)) *fixture {
	t.Helper()
	if handle == nil {
		handle = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		}
	}
	f := newFixture(t, handle)
	asURL, err := url.Parse(as.srv.URL)
	require.NoError(t, err)
	f.cfg.Binding.Slots[0].Hosts = append(f.cfg.Binding.Slots[0].Hosts, asURL.Host)
	f.cfg.Secret = func(context.Context, string) ([]byte, error) { return []byte(credential), nil }
	f.cfg.OAuth = &mcpproxy.OAuth{Grant: grant, ClientID: "keylatch-client", TokenURL: as.srv.URL + "/token"}
	return f
}

func TestRefreshTokenGrantSendsTheAccessTokenNotTheCredential(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	f.cfg.OAuth.Scope = "mcp:read"

	out := f.run(t, ping+ping)

	require.Len(t, out, 2)
	require.Len(t, f.remote.requests, 2)
	for _, r := range f.remote.requests {
		assert.Equal(t, "Bearer "+accessOne, r.auth)
	}
	forms := as.calls()
	require.Len(t, forms, 1, "a live access token is reused")
	assert.Equal(t, "refresh_token", forms[0].Get("grant_type"))
	assert.Equal(t, refreshCredential, forms[0].Get("refresh_token"))
	assert.Equal(t, "keylatch-client", forms[0].Get("client_id"))
	assert.Equal(t, "mcp:read", forms[0].Get("scope"))
	assert.Empty(t, forms[0].Get("client_secret"))
}

func TestClientCredentialsGrantSendsTheClientSecret(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantClientCredentials, clientSecret, nil)

	f.run(t, ping)

	forms := as.calls()
	require.Len(t, forms, 1)
	assert.Equal(t, "client_credentials", forms[0].Get("grant_type"))
	assert.Equal(t, clientSecret, forms[0].Get("client_secret"))
	assert.Empty(t, forms[0].Get("refresh_token"))
	assert.Equal(t, "Bearer "+accessOne, f.remote.requests[0].auth)
}

func TestAnExpiringAccessTokenIsRenewed(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, n int) {
		issue(map[bool]string{true: accessOne, false: accessTwo}[n == 1], 5)(w, nil, n)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)

	f.run(t, ping+ping)

	require.Len(t, f.remote.requests, 2)
	assert.Equal(t, "Bearer "+accessOne, f.remote.requests[0].auth)
	assert.Equal(t, "Bearer "+accessTwo, f.remote.requests[1].auth)
	assert.Len(t, as.calls(), 2)
}

func TestARefusedAccessTokenIsReplacedOnce(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, n int) {
		issue(map[bool]string{true: accessOne, false: accessTwo}[n == 1], 3600)(w, nil, n)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Header.Get("Authorization") == "Bearer "+accessOne {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	})

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], `"ok":true`)
	require.Len(t, f.remote.requests, 2)
	assert.Equal(t, "Bearer "+accessTwo, f.remote.requests[1].auth)
}

func TestAFreshTokenThatIsRefusedIsNotRetriedForever(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "401")
	assert.Len(t, f.remote.requests, 2, "one retry with a fresh token, then the error")
	assert.Len(t, as.calls(), 2)
}

func TestARotatedRefreshTokenIsStored(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, form url.Values, n int) {
		if n == 1 {
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","expires_in":5,"refresh_token":%q}`, accessOne, rotatedRefresh)
			return
		}
		issue(accessTwo, 3600)(w, form, n)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	current := refreshCredential
	f.cfg.Secret = func(context.Context, string) ([]byte, error) { return []byte(current), nil }
	f.cfg.OAuth.Rotate = func(_ context.Context, field string, token []byte) error {
		assert.Equal(t, "token", field)
		current = string(token)
		return nil
	}

	f.run(t, ping+ping)

	forms := as.calls()
	require.Len(t, forms, 2)
	assert.Equal(t, rotatedRefresh, forms[1].Get("refresh_token"), "the next exchange uses the stored replacement")
}

func TestARotationThatCannotBeStoredFailsTheRequest(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q}`, accessOne, rotatedRefresh)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	f.cfg.OAuth.Rotate = func(context.Context, string, []byte) error {
		return fmt.Errorf("vault is read-only: %s %s %s", refreshCredential, rotatedRefresh, accessOne)
	}

	out := f.run(t, ping+ping)

	require.Len(t, out, 2)
	for _, reply := range out {
		assert.Contains(t, reply, "could not be stored")
		for _, secret := range []string{refreshCredential, rotatedRefresh, accessOne} {
			assert.NotContains(t, reply, secret)
		}
	}
	assert.Empty(t, f.remote.requests)
}

func TestRotatedRefreshTokenRequiresAStore(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q}`, accessOne, rotatedRefresh)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	out := f.run(t, ping)
	require.Len(t, out, 1)
	assert.Contains(t, out[0], "no token store")
	assert.Empty(t, f.remote.requests)
}

func TestInvalidTokenMetadataNeverForwardsOrLeaksSecrets(t *testing.T) {
	for name, metadata := range map[string]string{
		"negative lifetime": `"expires_in":-1`,
		"overflow lifetime": `"expires_in":9223372036854775807`,
		"echoed token type": `"token_type":"` + refreshCredential + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
				_, _ = fmt.Fprintf(w, `{"access_token":%q,%s}`, accessOne, metadata)
			})
			f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
			out := f.run(t, ping)
			require.Len(t, out, 1)
			assert.Contains(t, out[0], `"error"`)
			assert.NotContains(t, out[0], refreshCredential)
			assert.NotContains(t, out[0], accessOne)
			assert.Empty(t, f.remote.requests)
		})
	}
}

func TestATokenEndpointRefusalIsReportedWithoutForwarding(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "invalid_grant")
	assert.NotContains(t, out[0], refreshCredential)
	assert.Empty(t, f.remote.requests)
}

func TestATokenEndpointErrorThatEchoesTheCredentialIsRedacted(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"bad token %s"}`, refreshCredential)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.NotContains(t, out[0], refreshCredential)
}

func TestOnlyBearerAccessTokensAreAccepted(t *testing.T) {
	as := newAuthServer(t, func(w http.ResponseWriter, _ url.Values, _ int) {
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"DPoP"}`, accessOne)
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "only bearer tokens are supported")
	assert.Empty(t, f.remote.requests)
}

func TestAMissingOAuthCredentialIsReported(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	f.cfg.Secret = func(context.Context, string) ([]byte, error) { return nil, nil }

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "has no token")
	assert.Empty(t, as.calls())
}

func TestAnUnreachableTokenEndpointIsReported(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
	as.srv.Close()

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "unreachable")
	assert.NotContains(t, out[0], refreshCredential)
}

func TestOAuthConfigurationIsValidated(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	for name, tc := range map[string]struct {
		change func(*mcpproxy.OAuth)
		want   string
	}{
		"unknown grant":    {func(o *mcpproxy.OAuth) { o.Grant = "password" }, "unknown OAuth grant"},
		"no client id":     {func(o *mcpproxy.OAuth) { o.ClientID = "" }, "client id"},
		"clear text":       {func(o *mcpproxy.OAuth) { o.TokenURL = "http://auth.example.com/token" }, "https"},
		"unbound host":     {func(o *mcpproxy.OAuth) { o.TokenURL = "https://evil.example.com/token" }, "outside the hosts"},
		"embedded login":   {func(o *mcpproxy.OAuth) { o.TokenURL = "https://user:pw@auth.example.com/token" }, "not a usable"},
		"not a url":        {func(o *mcpproxy.OAuth) { o.TokenURL = "::" }, "not a usable"},
		"unbound loopback": {func(o *mcpproxy.OAuth) { o.TokenURL = "http://127.0.0.1:1/token" }, "outside the hosts"},
	} {
		t.Run(name, func(t *testing.T) {
			f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, nil)
			tc.change(f.cfg.OAuth)
			err := mcpproxy.Run(context.Background(), f.cfg, strings.NewReader(ping), io.Discard)
			require.ErrorContains(t, err, tc.want)
			assert.Empty(t, f.remote.requests)
			assert.Empty(t, as.calls())
		})
	}
}

// discoveryRemote serves the protected-resource metadata of a remote MCP
// server alongside the MCP endpoint.
func discoveryRemote(authServers ...string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			_ = json.NewEncoder(w).Encode(map[string]any{"authorization_servers": authServers})
			return
		}
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
}

func TestTheTokenEndpointIsDiscovered(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	as.srv.Config.Handler.(*http.ServeMux).HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": as.srv.URL + "/token"})
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, discoveryRemote(as.srv.URL))
	f.cfg.OAuth.TokenURL = ""

	out := f.run(t, ping+ping)

	require.Len(t, out, 2)
	assert.Equal(t, "Bearer "+accessOne, f.remote.requests[len(f.remote.requests)-1].auth)
	assert.Len(t, as.calls(), 1, "the endpoint is discovered once")
}

func TestADiscoveredEndpointOutsideTheBoundHostsNeverGetsTheCredential(t *testing.T) {
	evilHits := 0
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHits++
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(evil.Close)
	as := newAuthServer(t, issue(accessOne, 3600))
	as.srv.Config.Handler.(*http.ServeMux).HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": evil.URL + "/token"})
	})
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, discoveryRemote(as.srv.URL))
	f.cfg.OAuth.TokenURL = ""

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "outside the hosts")
	assert.Zero(t, evilHits)
	assert.Empty(t, as.calls())
}

func TestAnAuthorizationServerOutsideTheBoundHostsIsNotAsked(t *testing.T) {
	evilHits := 0
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHits++ }))
	t.Cleanup(evil.Close)
	as := newAuthServer(t, issue(accessOne, 3600))
	f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, discoveryRemote(evil.URL))
	f.cfg.OAuth.TokenURL = ""

	out := f.run(t, ping)

	require.Len(t, out, 1)
	assert.Contains(t, out[0], "outside the hosts")
	assert.Zero(t, evilHits)
}

func TestDiscoveryFailuresAskForAnExplicitEndpoint(t *testing.T) {
	as := newAuthServer(t, issue(accessOne, 3600))
	for name, handle := range map[string]func(http.ResponseWriter, *http.Request, []byte){
		"no metadata":       nil,
		"no servers":        discoveryRemote(),
		"bad issuer":        discoveryRemote("::"),
		"no token endpoint": discoveryRemote(as.srv.URL),
	} {
		t.Run(name, func(t *testing.T) {
			f := oauthFixture(t, as, mcpproxy.GrantRefreshToken, refreshCredential, handle)
			f.cfg.OAuth.TokenURL = ""

			out := f.run(t, ping)

			require.Len(t, out, 1)
			assert.Contains(t, out[0], "mcpproxy:")
			assert.Empty(t, as.calls())
		})
	}
}
