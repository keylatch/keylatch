package strategies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAzureAuthority is the Microsoft Entra ID login host.
const DefaultAzureAuthority = "https://login.microsoftonline.com"

// ErrAzureScopeMismatch is returned when Entra ID issued a token for a
// resource other than the one requested. No token is returned with it.
var ErrAzureScopeMismatch = errors.New("azure_client_credentials: issued token does not match the requested resource")

// AzureToken is one access token for one resource.
type AzureToken struct {
	AccessToken []byte
	ExpiresAt   time.Time
}

// Zero wipes the token.
func (t *AzureToken) Zero() { clear(t.AccessToken) }

// AzureClientCredentialsStrategy mints an Entra ID token for an application's
// client credentials, limited to one resource.
type AzureClientCredentialsStrategy struct {
	tenant, clientID string
	getClientSecret  func(namespace string) ([]byte, error)
	federated        bool
	authority        string
	maxLifetime      time.Duration
	httpClient       *http.Client
	now              func() time.Time
}

// AzureOption configures an AzureClientCredentialsStrategy.
type AzureOption func(*AzureClientCredentialsStrategy)

// WithAzureMaxLifetime sets the longest token lifetime accepted. Entra ID
// chooses the lifetime itself, so a longer one is refused rather than
// shortened. The default is one hour.
func WithAzureMaxLifetime(d time.Duration) AzureOption {
	return func(s *AzureClientCredentialsStrategy) { s.maxLifetime = d }
}

// WithAzureAuthority points the strategy at another login host.
func WithAzureAuthority(authority string) AzureOption {
	return func(s *AzureClientCredentialsStrategy) { s.authority = strings.TrimRight(authority, "/") }
}

// NewAzureClientCredentialsStrategy creates the strategy for one application.
func NewAzureClientCredentialsStrategy(tenant, clientID string, getClientSecret func(namespace string) ([]byte, error), opts ...AzureOption) *AzureClientCredentialsStrategy {
	s := &AzureClientCredentialsStrategy{
		tenant: tenant, clientID: clientID, getClientSecret: getClientSecret,
		authority:   DefaultAzureAuthority,
		maxLifetime: MaxTokenLifetime,
		httpClient:  credentialHTTPClient(nil),
		now:         time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// NewAzureFederatedStrategy exchanges an external identity provider's assertion.
func NewAzureFederatedStrategy(tenant, clientID string, getAssertion func(namespace string) ([]byte, error), opts ...AzureOption) *AzureClientCredentialsStrategy {
	s := NewAzureClientCredentialsStrategy(tenant, clientID, getAssertion, opts...)
	s.federated = true
	return s
}

// Provider returns "azure".
func (s *AzureClientCredentialsStrategy) Provider() string { return "azure" }

// MintScoped requests a token for resource (an application ID URI or client
// ID) and checks that its audience is that resource.
func (s *AzureClientCredentialsStrategy) MintScoped(ctx context.Context, namespace, resource string) (AzureToken, error) {
	if resource == "" {
		return AzureToken{}, errors.New("azure_client_credentials: a resource is required")
	}
	secret, err := s.getClientSecret(namespace)
	if err != nil {
		return AzureToken{}, fmt.Errorf("azure_client_credentials: get client secret: %w", err)
	}
	defer clear(secret)
	if len(secret) == 0 {
		return AzureToken{}, errors.New("azure_client_credentials: empty client credential")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.clientID)
	if s.federated {
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", string(secret))
	} else {
		form.Set("client_secret", string(secret))
	}
	form.Set("scope", strings.TrimRight(resource, "/")+"/.default")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.authority+"/"+url.PathEscape(s.tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return AzureToken{}, fmt.Errorf("azure_client_credentials: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return AzureToken{}, fmt.Errorf("azure_client_credentials: http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return AzureToken{}, fmt.Errorf("azure_client_credentials: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return AzureToken{}, fmt.Errorf("azure_client_credentials: server returned %d", resp.StatusCode)
	}
	var reply struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &reply); err != nil || reply.AccessToken == "" || reply.ExpiresIn <= 0 {
		return AzureToken{}, fmt.Errorf("%w: incomplete reply", ErrAzureScopeMismatch)
	}
	if reply.ExpiresIn > int((s.maxLifetime+stsClockSkew)/time.Second) {
		return AzureToken{}, fmt.Errorf("%w: token lives %d seconds, longer than the %s allowed", ErrAzureScopeMismatch, reply.ExpiresIn, s.maxLifetime)
	}
	if aud := jwtAudience(reply.AccessToken); aud != strings.TrimRight(resource, "/") && aud != resource {
		return AzureToken{}, fmt.Errorf("%w: audience %q, wanted %q", ErrAzureScopeMismatch, aud, resource)
	}
	return AzureToken{
		AccessToken: []byte(reply.AccessToken),
		ExpiresAt:   s.now().Add(time.Duration(reply.ExpiresIn) * time.Second),
	}, nil
}

// jwtAudience reads the aud claim without verifying the signature: the token
// came straight from the token endpoint over TLS, and the claim is only
// compared with what was asked for.
func jwtAudience(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Aud string `json:"aud"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.Aud
}
