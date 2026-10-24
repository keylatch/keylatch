package providermint

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
)

// vaultFields are the keys of a dynamic secret that are injected into a
// command, by the field name the template declares.
var vaultFields = []string{"username", "password", "access_key", "secret_key", "security_token"}

func mintVault(ctx context.Context, r Request, p *config.VaultMintPolicy) (*Secret, error) {
	if err := r.rejectOtherKeys(ProviderVault); err != nil {
		return nil, err
	}
	path, err := r.oneScope("path")
	if err != nil {
		return nil, err
	}
	maxLease, err := mint.CheckVault(p, r.Caller, path)
	if err != nil {
		return nil, err
	}
	addr, err := r.config(ctx, "vault_addr")
	if err != nil {
		return nil, err
	}
	if !mint.ValidHTTPSEndpoint(addr) {
		return nil, fmt.Errorf("%w: the connection's vault_addr must be an https URL", ErrUsage)
	}
	strategy := strategies.NewVaultDynamicSecretStrategy(addr, p.Path, r.secretGetter(ctx, "vault_token"))
	lease, err := strategy.MintScoped(ctx, r.Namespace, strategies.VaultScope{MaxLease: maxLease})
	if err != nil {
		return nil, err
	}
	defer lease.Zero()

	leaseID := lease.LeaseID
	s := &Secret{
		Fields: map[string][]byte{}, ExpiresAt: lease.Expires, LeaseID: leaseID,
		Scope: map[string][]string{"path": {p.Path}},
		revoke: func(ctx context.Context) error {
			return strategies.NewVaultDynamicSecretStrategy(addr, p.Path, r.secretGetter(ctx, "vault_token")).Revoke(ctx, r.Namespace, leaseID)
		},
	}
	for _, f := range vaultFields {
		if v, ok := lease.Data[f].(string); ok && v != "" {
			s.Fields[f] = []byte(v)
		}
	}
	if len(s.Fields) == 0 {
		err := fmt.Errorf("%w: the secret has none of %v, so there is nothing to inject; it was revoked", strategies.ErrVaultLeaseMismatch, vaultFields)
		if rerr := s.revoke(ctx); rerr != nil {
			err = fmt.Errorf("%w (revoking it failed: %v)", err, rerr)
		}
		return nil, err
	}
	return s, nil
}

func mintGCP(ctx context.Context, r Request, p *config.GCPMintPolicy) (*Secret, error) {
	if err := r.rejectOtherKeys(ProviderGCP); err != nil {
		return nil, err
	}
	scopes, life, err := mint.CheckGCP(p, r.Caller, r.scopeValues("scope"))
	if err != nil {
		return nil, err
	}
	source := func(ns string) ([]byte, error) {
		key, err := r.secretGetter(ctx, "service_account_key")(ns)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		return strategies.GCPSourceTokenFromKey(key, r.Endpoints.GCPToken, nil)(ns)
	}
	var opts []strategies.GCPOption
	if r.Endpoints.GCPIAM != "" {
		opts = append(opts, strategies.WithGCPEndpoint(r.Endpoints.GCPIAM))
	}
	if r.Endpoints.GCPTokenInfo != "" {
		opts = append(opts, strategies.WithGCPTokenInfoURL(r.Endpoints.GCPTokenInfo))
	}
	tok, err := strategies.NewGCPImpersonationStrategy(p.ServiceAccount, source, opts...).
		MintScoped(ctx, r.Namespace, strategies.GCPScope{Scopes: scopes, Lifetime: life})
	if err != nil {
		return nil, err
	}
	return &Secret{
		Fields:    map[string][]byte{"access_token": tok.AccessToken},
		ExpiresAt: tok.ExpiresAt,
		Scope:     map[string][]string{"scope": scopes},
	}, nil
}

func mintAzure(ctx context.Context, r Request, p *config.AzureMintPolicy) (*Secret, error) {
	if err := r.rejectOtherKeys(ProviderAzure); err != nil {
		return nil, err
	}
	resource, err := r.oneScope("resource")
	if err != nil {
		return nil, err
	}
	life, err := mint.CheckAzure(p, r.Caller, resource)
	if err != nil {
		return nil, err
	}
	tenant, err := r.config(ctx, "tenant_id")
	if err != nil {
		return nil, err
	}
	clientID, err := r.config(ctx, "client_id")
	if err != nil {
		return nil, err
	}
	opts := []strategies.AzureOption{strategies.WithAzureMaxLifetime(life)}
	if r.Endpoints.AzureAuthority != "" {
		opts = append(opts, strategies.WithAzureAuthority(r.Endpoints.AzureAuthority))
	}
	strategy := strategies.NewAzureClientCredentialsStrategy(tenant, clientID, r.secretGetter(ctx, "client_secret"), opts...)
	if p.Authentication == "federated" {
		strategy = strategies.NewAzureFederatedStrategy(tenant, clientID, r.secretGetter(ctx, "client_assertion"), opts...)
	}
	tok, err := strategy.MintScoped(ctx, r.Namespace, p.Resource)
	if err != nil {
		return nil, err
	}
	return &Secret{
		Fields:    map[string][]byte{"access_token": tok.AccessToken},
		ExpiresAt: tok.ExpiresAt,
		Scope:     map[string][]string{"resource": {p.Resource}},
	}, nil
}

func mintOAuth(ctx context.Context, r Request, p *config.OAuthMintPolicy) (*Secret, error) {
	if err := r.rejectOtherKeys(ProviderOAuth); err != nil {
		return nil, err
	}
	scopes, life, err := mint.CheckOAuth(p, r.Caller, r.scopeValues("scope"))
	if err != nil {
		return nil, err
	}
	clientID, err := r.config(ctx, "client_id")
	if err != nil {
		return nil, err
	}
	clientSecret, err := r.secretGetter(ctx, "client_secret")("")
	if err != nil {
		return nil, err
	}
	defer clear(clientSecret)
	refresh := r.secretGetter(ctx, "refresh_token")
	strategy := strategies.NewOAuthRefreshStrategy(ProviderOAuth, p.TokenEndpoint, clientID, string(clientSecret),
		func(_, ns string) ([]byte, error) { return refresh(ns) }, strategies.WithScopes(scopes...))
	tok, err := strategy.MintScoped(ctx, r.Connection, r.Namespace, life)
	if err != nil {
		return nil, err
	}
	return &Secret{
		Fields:    map[string][]byte{"access_token": tok.AccessToken},
		ExpiresAt: tok.ExpiresAt,
		Scope:     map[string][]string{"scope": scopes},
	}, nil
}
