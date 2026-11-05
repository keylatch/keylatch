package cli

import (
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/paths"
)

// NewMintSessions returns the minter the daemon uses for placeholder sessions.
// It reads key material from the configured store and the mint policy from the
// operator's own config file, as the mint command does.
func NewMintSessions(lookup llmcontext.Lookup, em audit.Emitter) *mintsession.Minter {
	cfg := config.Default()
	if loaded, err := config.Load(paths.Config(lookup)); err == nil {
		cfg = loaded
	}
	return mintsession.New(mintsession.Config{
		Store:   newDispatchedStore(cfg, lookup),
		APIBase: strategies.DefaultGitHubAPIBase,
		Policy:  operatorConfig,
		Audit:   em,
	})
}
