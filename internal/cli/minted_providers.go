package cli

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// mintEndpoints replaces the provider hosts in tests.
var mintEndpoints providermint.Endpoints

// providerCredential is a Vault, GCP, Azure or OAuth credential minted for one
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
	return &providerCredential{secret: secret}, nil
}
