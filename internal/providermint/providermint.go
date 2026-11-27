// Package providermint mints short-lived credentials from Vault dynamic
// secrets, GCP service-account impersonation, Azure client credentials and
// OAuth refresh tokens. The policy in the operator's config is checked before
// any stored credential is read; the provider's reply must match the request
// or nothing is returned; every mint is audited without its value; and a
// lease the provider can revoke is revoked when the Secret is closed.
package providermint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
)

// Provider names of the templates this package mints for.
const (
	ProviderVault = "hashicorp-vault"
	ProviderGCP   = "gcp"
	ProviderAzure = "azure"
	ProviderOAuth = "oauth-refresh"
	ProviderAWS   = "aws"
)

// ErrUsage is wrapped when the request cannot be understood.
var ErrUsage = errors.New("providermint: invalid request")

const revokeTimeout = 10 * time.Second

// Supports reports whether Mint handles the template's provider.
func Supports(provider string) bool {
	return slices.Contains([]string{ProviderVault, ProviderGCP, ProviderAzure, ProviderOAuth, ProviderAWS}, provider)
}

// ScopeKeys are the --scope keys a provider accepts.
func ScopeKeys(provider string) []string {
	switch provider {
	case ProviderAWS:
		return []string{"role_arn", "duration"}
	case ProviderVault:
		return []string{"path"}
	case ProviderGCP, ProviderOAuth:
		return []string{"scope"}
	case ProviderAzure:
		return []string{"resource"}
	}
	return nil
}

// ParseScope turns k=v flags into a scope. A key may repeat.
func ParseScope(provider string, pairs []string) (map[string][]string, error) {
	keys := ScopeKeys(provider)
	scope := map[string][]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || v == "" || !slices.Contains(keys, k) {
			return nil, fmt.Errorf("%w: --scope %q must be %s=<value>", ErrUsage, p, strings.Join(keys, "|"))
		}
		scope[k] = append(scope[k], v)
	}
	if provider != ProviderGCP && provider != ProviderOAuth {
		for k, v := range scope {
			if len(v) > 1 {
				return nil, fmt.Errorf("%w: --scope %s may be given once", ErrUsage, k)
			}
		}
	}
	return scope, nil
}

// Endpoints replace the providers' hosts. Only tests set them.
type Endpoints struct {
	GCPIAM, GCPToken, GCPTokenInfo, AzureAuthority, AWSSTS string
}

// Request is one mint.
type Request struct {
	Store      connections.Store
	Template   registry.ConnectionTemplate
	Config     config.Config
	Connection string
	Namespace  string
	Caller     mint.CallerKind
	// Scope narrows what the policy allows; empty selects the policy's.
	Scope       map[string][]string
	Audit       audit.Emitter
	RuntimeMode string
	Endpoints   Endpoints
}

// Secret is one minted credential. It holds values in memory only.
type Secret struct {
	// Fields are the credential's values by minted field name.
	Fields    map[string][]byte
	ExpiresAt time.Time
	// Scope is what was granted.
	Scope map[string][]string
	// LeaseID is set for Vault; the lease is revoked by Close.
	LeaseID string

	revoke func(context.Context) error
	audit  func(ctx context.Context, outcome audit.Outcome, reason string) error
}

// Value returns a copy of a minted field, or false when the provider issued none.
func (s *Secret) Value(field string) ([]byte, bool) {
	v, ok := s.Fields[field]
	return slices.Clone(v), ok
}

// Release wipes the values but leaves the lease to run out. A caller that
// hands the credential to another process (keylatch mint) cannot revoke it
// first; the lease is already capped at an hour.
func (s *Secret) Release() {
	s.revoke = nil
	_ = s.Close()
}

// Close wipes the values and revokes the lease where the provider supports it.
// It records the revocation; a failed revocation is returned.
func (s *Secret) Close() error {
	for _, v := range s.Fields {
		clear(v)
	}
	s.Fields = nil
	if s.revoke == nil {
		return nil
	}
	revoke := s.revoke
	s.revoke = nil
	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	err := revoke(ctx)
	reason := "lease_revoked"
	outcome := audit.OutcomeOK
	if err != nil {
		reason, outcome = "revoke_failed", audit.OutcomeError
	}
	_ = s.audit(ctx, outcome, reason)
	return err
}

// Mint checks the policy, reads the connection's stored credential, mints and
// audits. It fails without the audit log, because Keylatch does not mint
// unaudited credentials.
func Mint(ctx context.Context, r Request) (*Secret, error) {
	if !Supports(r.Template.Provider) {
		return nil, fmt.Errorf("%w: %s has no mint strategy", ErrUsage, r.Template.Provider)
	}
	var mintPolicy config.MintPolicy
	if cp, ok := r.Config.Connections[r.Connection]; ok && cp.Mint != nil {
		mintPolicy = *cp.Mint
	}
	if err := audit.Ready(r.Audit); err != nil {
		return nil, fmt.Errorf("the audit log is not available (%v); Keylatch does not mint unaudited credentials", err)
	}

	var (
		secret *Secret
		err    error
	)
	switch r.Template.Provider {
	case ProviderAWS:
		secret, err = mintAWS(ctx, r, mintPolicy.AWS)
	case ProviderVault:
		secret, err = mintVault(ctx, r, mintPolicy.Vault)
	case ProviderGCP:
		secret, err = mintGCP(ctx, r, mintPolicy.GCP)
	case ProviderAzure:
		secret, err = mintAzure(ctx, r, mintPolicy.Azure)
	case ProviderOAuth:
		secret, err = mintOAuth(ctx, r, mintPolicy.OAuth)
	}
	if err != nil {
		var field *mintsession.FieldError
		refused := errors.Is(err, mint.ErrDenied) || errors.Is(err, mint.ErrInvalidProviderPolicy) || errors.Is(err, mint.ErrInvalidAWSPolicy) || errors.Is(err, ErrUsage) || errors.As(err, &field)
		if !refused {
			reason := "provider_error"
			if isMismatch(err) {
				reason = "scope_mismatch"
			}
			_ = emit(ctx, r, &Secret{}, audit.OutcomeError, reason)
		}
		return nil, err
	}

	secret.audit = func(ctx context.Context, outcome audit.Outcome, reason string) error {
		return emit(ctx, r, secret, outcome, reason)
	}
	if err := secret.audit(ctx, audit.OutcomeOK, ""); err != nil {
		if rerr := secret.Close(); rerr != nil {
			err = fmt.Errorf("%w; revoking the lease failed: %v", err, rerr)
		}
		return nil, fmt.Errorf("the audit line could not be written: %w", err)
	}
	return secret, nil
}

func emit(ctx context.Context, r Request, s *Secret, outcome audit.Outcome, reason string) error {
	extra := map[string]any{
		"connection":  r.Connection,
		"namespace":   r.Namespace,
		"provider":    r.Template.Provider,
		"scope":       formatScope(s.Scope),
		"caller_kind": string(r.Caller),
	}
	if !s.ExpiresAt.IsZero() {
		extra["expires_at"] = s.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if reason != "" {
		extra["reason"] = reason
	}
	mode := r.RuntimeMode
	if mode == "" {
		mode = "cli"
	}
	return r.Audit.Emit(ctx, audit.Event{
		Timestamp: time.Now().UTC(), Action: audit.ActionMint, Outcome: outcome, RuntimeMode: mode, Extra: extra,
	})
}

func formatScope(scope map[string][]string) string {
	parts := make([]string, 0, len(scope))
	for _, k := range slices.Sorted(maps.Keys(scope)) {
		v := slices.Clone(scope[k])
		slices.Sort(v)
		parts = append(parts, k+"="+strings.Join(v, ","))
	}
	return strings.Join(parts, ";")
}

func (r Request) scopeValues(key string) []string { return r.Scope[key] }

func (r Request) oneScope(key string) (string, error) {
	v := r.scopeValues(key)
	switch len(v) {
	case 0:
		return "", nil
	case 1:
		return v[0], nil
	}
	return "", fmt.Errorf("%w: --scope %s may be given once", ErrUsage, key)
}

// rejectOtherKeys fails closed on a scope key the provider does not know.
func (r Request) rejectOtherKeys(provider string) error {
	for k := range r.Scope {
		if !slices.Contains(ScopeKeys(provider), k) {
			return fmt.Errorf("%w: --scope %s does not apply to %s", ErrUsage, k, provider)
		}
	}
	return nil
}

func (r Request) read(ctx context.Context, secret bool, name string) ([]byte, error) {
	path := connections.ConfigFieldPath(r.Namespace, r.Template.Category, r.Connection, name)
	if secret {
		path = connections.SecretFieldPath(r.Namespace, r.Template.Category, r.Connection, name)
	}
	v, _, err := r.Store.Get(ctx, path)
	if errors.Is(err, backend.ErrNotFound) || (err == nil && len(v) == 0) {
		return nil, &mintsession.FieldError{Field: name, Missing: true, Err: backend.ErrNotFound}
	}
	if err != nil {
		return nil, &mintsession.FieldError{Field: name, Err: err}
	}
	return v, nil
}

func (r Request) config(ctx context.Context, name string) (string, error) {
	v, err := r.read(ctx, false, name)
	return strings.TrimSpace(string(v)), err
}

func isMismatch(err error) bool {
	return errors.Is(err, strategies.ErrVaultLeaseMismatch) || errors.Is(err, strategies.ErrGCPScopeMismatch) ||
		errors.Is(err, strategies.ErrAzureScopeMismatch) || errors.Is(err, strategies.ErrOAuthScopeMismatch) || errors.Is(err, strategies.ErrAWSScopeMismatch)
}

func (r Request) secretGetter(ctx context.Context, name string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) {
		v, err := r.read(ctx, true, name)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(v), nil
	}
}
