package cli

import (
	"slices"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/registry"
)

// gatewayGitHubMintOptions resolves the connection and operator policy behind
// `gateway up --github-mint`. The policy comes from the operator's config
// file only, so the gateway's environment cannot widen what is minted.
func gatewayGitHubMintOptions(connection string) (*gateway.GitHubMintOptions, error) {
	tmpl, err := registry.Get(connection)
	if err != nil || !slices.ContainsFunc(tmpl.Capabilities, func(cp registry.Capability) bool { return cp.Name == mintCapability }) {
		return nil, NewUsageError("gateway up: --github-mint %q is not a connection type that can mint (use a github-app connection)", connection)
	}
	cfg, err := mintPolicyConfig()
	if err != nil {
		return nil, NewPolicyDeny("gateway up: the mint policy cannot be read: %v", err)
	}
	policy := githubAppMintPolicy(cfg, connection)
	if policy == nil {
		return nil, NewPolicyDeny("gateway up: connection %q has no mint.github_app policy in the operator config", connection)
	}
	return &gateway.GitHubMintOptions{
		Connection: connection,
		Namespace:  "default",
		Category:   tmpl.Category,
		Policy:     policy,
	}, nil
}
