package mint

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/config"
)

// MaxProviderTTL is the longest max_ttl an Azure or OAuth policy may set: the
// provider picks the lifetime of those tokens and Entra ID issues up to 90
// minutes. Every other mint is capped at MaxTTL.
const MaxProviderTTL = 90 * time.Minute

// ErrInvalidProviderPolicy is wrapped when a mint.vault, mint.gcp, mint.azure
// or mint.oauth policy is itself invalid.
var ErrInvalidProviderPolicy = errors.New("invalid mint policy")

func invalid(kind, format string, args ...any) error {
	return fmt.Errorf("%w: mint.%s: %s", ErrInvalidProviderPolicy, kind, fmt.Sprintf(format, args...))
}

func validateCallers(kind string, callers []string) error {
	for _, c := range callers {
		switch CallerKind(c) {
		case CallerService, CallerHost, CallerHuman:
		case CallerAgent:
			return invalid(kind, "agent sessions can never mint")
		default:
			return invalid(kind, "unknown caller kind %q", c)
		}
	}
	return nil
}

func checkCaller(kind string, callers []string, caller CallerKind) error {
	if caller == CallerAgent {
		return fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	allowed := defaultCallers
	if len(callers) > 0 {
		allowed = callerKinds(callers)
	}
	if !slices.Contains(allowed, caller) {
		return fmt.Errorf("%w: caller kind %q is not allowed to mint from a %s connection", ErrDenied, caller, kind)
	}
	return nil
}

func ttl(kind string, seconds int, ceiling time.Duration) (time.Duration, error) {
	if seconds < 0 || seconds > int(ceiling/time.Second) {
		return 0, invalid(kind, "max_ttl %d must be between 1 and %d seconds", seconds, int(ceiling.Seconds()))
	}
	if seconds == 0 {
		return MaxTTL, nil
	}
	return time.Duration(seconds) * time.Second, nil
}

// ValidHTTPSEndpoint reports whether raw is an https URL, or http on a
// loopback host (a local test server or SSH tunnel).
func ValidHTTPSEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// CheckVault decides whether caller may read path as a dynamic secret and
// returns the lease ceiling. An empty path selects the policy's path.
func CheckVault(p *config.VaultMintPolicy, caller CallerKind, path string) (time.Duration, error) {
	if caller == CallerAgent {
		return 0, fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	if p == nil {
		return 0, fmt.Errorf("%w: the connection has no mint.vault policy", ErrDenied)
	}
	if err := validateCallers("vault", p.Callers); err != nil {
		return 0, err
	}
	if strings.Trim(p.Path, "/") == "" {
		return 0, invalid("vault", "path is required")
	}
	lease, err := ttl("vault", p.MaxTTL, MaxTTL)
	if err != nil {
		return 0, err
	}
	if err := checkCaller("vault", p.Callers, caller); err != nil {
		return 0, err
	}
	if path != "" && strings.Trim(path, "/") != strings.Trim(p.Path, "/") {
		return 0, fmt.Errorf("%w: path %q is not the policy's path", ErrDenied, path)
	}
	return lease, nil
}

// CheckGCP decides whether caller may mint a token with scopes and returns the
// scopes to request and the lifetime. No scopes selects all the policy's.
func CheckGCP(p *config.GCPMintPolicy, caller CallerKind, scopes []string) ([]string, time.Duration, error) {
	if caller == CallerAgent {
		return nil, 0, fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	if p == nil {
		return nil, 0, fmt.Errorf("%w: the connection has no mint.gcp policy", ErrDenied)
	}
	if err := validateCallers("gcp", p.Callers); err != nil {
		return nil, 0, err
	}
	if !strings.Contains(p.ServiceAccount, "@") || len(p.Scopes) == 0 {
		return nil, 0, invalid("gcp", "service_account (an email) and at least one scope are required")
	}
	life, err := ttl("gcp", p.MaxTTL, MaxTTL)
	if err != nil {
		return nil, 0, err
	}
	if err := checkCaller("gcp", p.Callers, caller); err != nil {
		return nil, 0, err
	}
	granted, err := withinScopes(p.Scopes, scopes)
	return granted, life, err
}

// CheckAzure decides whether caller may mint a token for resource and returns
// the lifetime ceiling. An empty resource selects the policy's.
func CheckAzure(p *config.AzureMintPolicy, caller CallerKind, resource string) (time.Duration, error) {
	if caller == CallerAgent {
		return 0, fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	if p == nil {
		return 0, fmt.Errorf("%w: the connection has no mint.azure policy", ErrDenied)
	}
	if err := validateCallers("azure", p.Callers); err != nil {
		return 0, err
	}
	if p.Resource == "" || strings.ContainsAny(p.Resource, " \t\r\n") {
		return 0, invalid("azure", "resource is required")
	}
	if p.Authentication != "" && p.Authentication != "client_secret" && p.Authentication != "federated" {
		return 0, invalid("azure", "authentication must be client_secret or federated")
	}
	life, err := ttl("azure", p.MaxTTL, MaxProviderTTL)
	if err != nil {
		return 0, err
	}
	if err := checkCaller("azure", p.Callers, caller); err != nil {
		return 0, err
	}
	if resource != "" && resource != p.Resource {
		return 0, fmt.Errorf("%w: resource %q is not the policy's resource", ErrDenied, resource)
	}
	return life, nil
}

// CheckOAuth decides whether caller may mint a token with scopes and returns
// the scopes to request and the lifetime ceiling. No scopes selects all the
// policy's.
func CheckOAuth(p *config.OAuthMintPolicy, caller CallerKind, scopes []string) ([]string, time.Duration, error) {
	if caller == CallerAgent {
		return nil, 0, fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	if p == nil {
		return nil, 0, fmt.Errorf("%w: the connection has no mint.oauth policy", ErrDenied)
	}
	if err := validateCallers("oauth", p.Callers); err != nil {
		return nil, 0, err
	}
	if !ValidHTTPSEndpoint(p.TokenEndpoint) || len(p.Scopes) == 0 {
		return nil, 0, invalid("oauth", "token_endpoint (https) and at least one scope are required")
	}
	life, err := ttl("oauth", p.MaxTTL, MaxProviderTTL)
	if err != nil {
		return nil, 0, err
	}
	if err := checkCaller("oauth", p.Callers, caller); err != nil {
		return nil, 0, err
	}
	granted, err := withinScopes(p.Scopes, scopes)
	return granted, life, err
}

func withinScopes(allowed, requested []string) ([]string, error) {
	for _, s := range allowed {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return nil, fmt.Errorf("%w: every scope must be a nonempty token without whitespace", ErrInvalidProviderPolicy)
		}
	}
	if len(requested) == 0 {
		return slices.Clone(allowed), nil
	}
	for _, s := range requested {
		if !slices.Contains(allowed, s) {
			return nil, fmt.Errorf("%w: scope %q is not in the policy's scopes", ErrDenied, s)
		}
	}
	return slices.Clone(requested), nil
}
