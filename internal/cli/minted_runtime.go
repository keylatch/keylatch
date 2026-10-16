package cli

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// mintedOpener returns the opener the minted runtime uses: it applies the
// connection's mint policy, which the operator keeps in their own config, and
// mints with the template's strategy.
func mintedOpener(cfg config.Config, em audit.Emitter) runner.MintOpener {
	minter := mintsession.New(mintsession.Config{
		Store:   mintStore(cfg),
		APIBase: mintGitHubAPIBase,
		Policy:  mintPolicyConfig,
		Audit:   em,
	})
	return func(ctx context.Context, tmpl registry.ConnectionTemplate, req runner.MintOpenRequest) (runner.MintedCredential, error) {
		if tmpl.Provider == "aws" {
			opCfg, err := mintPolicyConfig()
			if err != nil {
				return nil, fmt.Errorf("%w: the mint policy cannot be read: %v", mint.ErrDenied, err)
			}
			return openAWS(ctx, mintStore(cfg), opCfg, em, tmpl, req)
		}
		cred, err := minter.Open(ctx, mintsession.Request{
			Connection:  req.Connection,
			Namespace:   req.Namespace,
			Caller:      req.Caller,
			RuntimeMode: "minted",
		})
		if err != nil {
			return nil, err
		}
		return cred, nil
	}
}
