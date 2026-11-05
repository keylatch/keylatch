package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/registry"
)

// OAuth grants the proxy can use. The connection's header-slot field holds
// the long-lived credential of the grant: the refresh token, or the client
// secret. The agent never sees it or the access tokens made from it.
const (
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

const (
	// tokenSkew refreshes an access token this long before it expires.
	tokenSkew = 30 * time.Second
	// defaultTokenLifetime applies when the server omits expires_in.
	defaultTokenLifetime = time.Hour
	maxTokenResponse     = 1 << 20
)

// OAuth makes the proxy obtain its own access tokens for a remote MCP server
// that does not accept a static bearer token.
type OAuth struct {
	Grant    string
	ClientID string
	Scope    string
	// TokenURL is the token endpoint. When empty it is discovered from the
	// remote server's protected-resource metadata (RFC 9728) and the
	// authorization server's metadata (RFC 8414).
	TokenURL string
	// Rotate stores a refresh token the server issued in place of the one
	// held in field. Without it a rotated token is dropped and the old one is
	// reused.
	Rotate func(ctx context.Context, field string, refreshToken []byte) error
}

type oauthState struct {
	cfg      OAuth
	p        *proxy
	endpoint string
	access   []byte
	expires  time.Time
}

func (o *oauthState) validate() error {
	switch o.cfg.Grant {
	case GrantRefreshToken, GrantClientCredentials:
	default:
		return fmt.Errorf("mcpproxy: unknown OAuth grant %q", o.cfg.Grant)
	}
	if o.cfg.ClientID == "" {
		return errors.New("mcpproxy: OAuth needs a client id")
	}
	if o.cfg.TokenURL != "" {
		if _, err := o.boundEndpoint(o.cfg.TokenURL); err != nil {
			return err
		}
	}
	return nil
}

// token returns a usable access token, asking the token endpoint when the
// cached one is missing or about to expire. The caller owns the copy.
func (o *oauthState) token(ctx context.Context) ([]byte, error) {
	if len(o.access) == 0 || !time.Now().Add(tokenSkew).Before(o.expires) {
		if err := o.fetch(ctx); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), o.access...), nil
}

// reject drops the cached access token after the remote refused it. It
// reports whether there was one to drop, so a fresh token is worth trying.
func (o *oauthState) reject() bool {
	had := len(o.access) > 0
	clear(o.access)
	o.access = nil
	return had
}

func (o *oauthState) fetch(ctx context.Context) error {
	credential, err := o.p.cfg.Secret(ctx, o.p.slot.Field)
	if err != nil || len(credential) == 0 {
		return fmt.Errorf("the connection %s has no %s", o.p.cfg.Connection, o.p.slot.Field)
	}
	defer clear(credential)
	matcher := redactor.NewMatcher(credential)

	endpoint, err := o.tokenEndpoint(ctx)
	if err != nil {
		return err
	}
	form := url.Values{"grant_type": {o.cfg.Grant}, "client_id": {o.cfg.ClientID}}
	if o.cfg.Scope != "" {
		form.Set("scope", o.cfg.Scope)
	}
	if o.cfg.Grant == GrantRefreshToken {
		form.Set("refresh_token", string(credential))
	} else {
		form.Set("client_secret", string(credential))
	}
	body, status, err := o.post(ctx, endpoint, form)
	if err != nil {
		return fmt.Errorf("the OAuth token endpoint is unreachable: %s", matcher.Redact([]byte(err.Error())))
	}
	defer clear(body)
	var tr struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	decodeErr := json.Unmarshal(body, &tr)
	matcher = redactor.NewMatcher(credential, []byte(tr.AccessToken), []byte(tr.RefreshToken))
	if status != http.StatusOK || decodeErr != nil || tr.AccessToken == "" {
		reason := tr.Error
		if reason == "" {
			reason = fmt.Sprintf("status %d", status)
		}
		return fmt.Errorf("the OAuth token endpoint refused the request: %s", matcher.Redact([]byte(reason)))
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return errors.New("the OAuth token endpoint issued an unsupported token type; only bearer tokens are supported")
	}
	if tr.ExpiresIn < 0 || tr.ExpiresIn > int64((1<<63-1)/time.Second) {
		return errors.New("the OAuth token endpoint issued an invalid token lifetime")
	}
	lifetime := defaultTokenLifetime
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	if o.cfg.Grant == GrantRefreshToken && tr.RefreshToken != "" && tr.RefreshToken != string(credential) {
		if o.cfg.Rotate == nil {
			return errors.New("the OAuth server rotated the refresh token but no token store is configured")
		}
		rotated := []byte(tr.RefreshToken)
		defer clear(rotated)
		if err := o.cfg.Rotate(ctx, o.p.slot.Field, rotated); err != nil {
			return fmt.Errorf("the OAuth server rotated the refresh token and it could not be stored: %s", matcher.Redact([]byte(err.Error())))
		}
	}
	clear(o.access)
	o.access, o.expires = []byte(tr.AccessToken), time.Now().Add(lifetime)
	return nil
}

func (o *oauthState) post(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return o.do(req)
}

func (o *oauthState) do(req *http.Request) ([]byte, int, error) {
	resp, err := o.p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	return body, resp.StatusCode, err
}

func (o *oauthState) tokenEndpoint(ctx context.Context) (string, error) {
	if o.endpoint != "" {
		return o.endpoint, nil
	}
	if o.cfg.TokenURL != "" {
		o.endpoint = o.cfg.TokenURL
		return o.endpoint, nil
	}
	issuer, err := o.discoverIssuer(ctx)
	if err != nil {
		return "", err
	}
	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := o.getJSON(ctx, wellKnown(issuer, "oauth-authorization-server"), &meta); err != nil || meta.TokenEndpoint == "" {
		return "", fmt.Errorf("mcpproxy: %s publishes no OAuth token endpoint; pass one explicitly", issuer)
	}
	endpoint, err := o.boundEndpoint(meta.TokenEndpoint)
	if err != nil {
		return "", err
	}
	o.endpoint = endpoint
	return endpoint, nil
}

// discoverIssuer reads the authorization server the remote MCP server names.
func (o *oauthState) discoverIssuer(ctx context.Context) (*url.URL, error) {
	var meta struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	target := o.p.target
	err := o.getJSON(ctx, wellKnown(target, "oauth-protected-resource"), &meta)
	if err != nil || len(meta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("mcpproxy: %s names no OAuth authorization server; pass the token endpoint explicitly", target.Host)
	}
	issuer, err := url.Parse(meta.AuthorizationServers[0])
	if err != nil || issuer.Host == "" {
		return nil, fmt.Errorf("mcpproxy: %s names an invalid authorization server", target.Host)
	}
	if _, err := o.boundEndpoint(issuer.String()); err != nil {
		return nil, err
	}
	return issuer, nil
}

func (o *oauthState) getJSON(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	body, status, err := o.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d", status)
	}
	return json.NewDecoder(bytes.NewReader(body)).Decode(into)
}

// boundEndpoint accepts an OAuth URL only when the credential may be sent to
// it: https (or loopback) and a host the credential's slot is bound to. A
// remote server cannot redirect the refresh token to a host of its choosing.
func (o *oauthState) boundEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("mcpproxy: %q is not a usable OAuth URL", raw)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return "", fmt.Errorf("mcpproxy: the OAuth URL %s must use https", raw)
	}
	authority := u.Host
	if u.Port() == "" {
		authority = net.JoinHostPort(u.Hostname(), map[string]string{"https": "443", "http": "80"}[u.Scheme])
	}
	for _, h := range o.p.slot.Hosts {
		if registry.MatchAuthority(h, authority) {
			return raw, nil
		}
	}
	return "", fmt.Errorf("mcpproxy: the OAuth URL %s is outside the hosts the connection is bound to", raw)
}

// wellKnown builds the RFC 8615 metadata URL for an issuer or resource: the
// well-known segment goes between the host and the path.
func wellKnown(base *url.URL, name string) string {
	u := *base
	path := strings.TrimSuffix(base.Path, "/")
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/.well-known/"+name+path, "", "", ""
	return u.String()
}
