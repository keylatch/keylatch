package cli

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/cloudcreds"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// mintEndpoints replaces the provider hosts in tests.
var mintEndpoints providermint.Endpoints

// providerCredential is a Vault or OAuth credential minted for one
// run. Closing it wipes the values and revokes the Vault lease.
type providerCredential struct{ secret *providermint.Secret }

func (c *providerCredential) Value(_ context.Context, field string) ([]byte, error) {
	v, ok := c.secret.Value(field)
	if !ok {
		return nil, runner.ErrMintedFieldAbsent
	}
	return v, nil
}

func (c *providerCredential) Close() { _ = c.secret.Close() }

// openProvider mints at the start of the run, with the scope the connection's
// policy grants.
func openProvider(ctx context.Context, cfg config.Config, em audit.Emitter, tmpl registry.ConnectionTemplate, req runner.MintOpenRequest) (runner.MintedCredential, error) {
	opCfg, err := mintPolicyConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: the mint policy cannot be read: %v", mint.ErrDenied, err)
	}
	secret, err := providermint.Mint(ctx, providermint.Request{
		Store: mintStore(cfg), Template: tmpl, Config: opCfg, Connection: req.Connection, Namespace: req.Namespace,
		Caller: req.Caller, Audit: em, RuntimeMode: "minted", Endpoints: mintEndpoints,
	})
	if err != nil {
		return nil, err
	}
	if tmpl.Provider == "gcp" || tmpl.Provider == "azure" {
		endpoint := cloudcreds.Config{Provider: tmpl.Provider, Connection: req.Connection, Initial: secret, Audit: em}
		policy := opCfg.Connections[req.Connection].Mint
		if tmpl.Provider == "gcp" {
			endpoint.Account = policy.GCP.ServiceAccount
			endpoint.Scopes = secret.Scope["scope"]
		} else {
			endpoint.Resource = policy.Azure.Resource
		}
		return openMetadataCredential(ctx, endpoint)
	}
	return &providerCredential{secret: secret}, nil
}

type metadataCredential struct {
	server   *cloudcreds.Server
	provider string
}

func openMetadataCredential(ctx context.Context, cfg cloudcreds.Config) (runner.MintedCredential, error) {
	server, err := cloudcreds.Start(ctx, cfg)
	if err != nil {
		if cfg.Initial != nil {
			_ = cfg.Initial.Close()
		}
		return nil, err
	}
	return &metadataCredential{server: server, provider: cfg.Provider}, nil
}

func (c *metadataCredential) Value(_ context.Context, field string) ([]byte, error) {
	switch {
	case c.provider == "gcp" && field == "metadata_host":
		return []byte(c.server.MetadataHost()), nil
	case c.provider == "azure" && field == "identity_endpoint":
		return []byte(c.server.IdentityEndpoint()), nil
	case c.provider == "azure" && field == "identity_header":
		return []byte(c.server.IdentityHeader()), nil
	default:
		return nil, runner.ErrMintedFieldAbsent
	}
}

func (c *metadataCredential) Close() { c.server.Close() }

func (c *metadataCredential) RedactionValues() [][]byte { return c.server.RedactionValues() }
