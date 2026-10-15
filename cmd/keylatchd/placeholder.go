package main

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/vault"
)

// vaultResolver reads a connection's secret field from the configured backend
// at the moment the proxy substitutes it.
type vaultResolver struct {
	cfg config.Config
	env llmcontext.Lookup
	log audit.Emitter
}

func (r vaultResolver) Resolve(ctx context.Context, connection, field string) ([]byte, error) {
	tmpl, err := registry.Get(connection)
	if err != nil {
		return nil, err
	}
	if tmpl.IsMinted(field) {
		return nil, fmt.Errorf("%s.%s is minted at use time and is not stored", connection, field)
	}
	category := tmpl.Category
	if category == "" {
		category = "ai"
	}
	ctx = audit.WithEmitter(ctx, r.log)
	return vault.Get(ctx, "default/"+category+"/"+connection+"/"+field, r.cfg, r.env)
}

// newPlaceholders opens the audit log and builds the manager that serves tier
// D3, with the function that opens minted credentials for it. The returned
// function releases the audit log.
func newPlaceholders(env llmcontext.Lookup) (*placeholder.Manager, control.MintFunc, func(), error) {
	logger, closeLog, err := cli.OpenAuditLogger()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("audit log: %w", err)
	}
	cfg := config.Default()
	if loaded, err := config.Load(paths.Config(env)); err == nil {
		cfg = loaded
	}
	em := audit.AsEmitter(logger)
	mgr, err := placeholder.NewManager(placeholder.Config{Resolver: vaultResolver{cfg: cfg, env: env, log: em}, Audit: em})
	if err != nil {
		closeLog()
		return nil, nil, nil, err
	}
	return mgr, mintFunc(cli.NewMintSessions(env, em)), func() { mgr.Close(); closeLog() }, nil
}

func mintFunc(m *mintsession.Minter) control.MintFunc {
	return func(ctx context.Context, kind control.Kind, rr *control.RunRequest) (placeholder.Credential, error) {
		cred, err := m.Open(ctx, mintsession.Request{
			Connection:  rr.Connection,
			Repository:  rr.Repository,
			Permissions: rr.Permissions,
			Caller:      mint.CallerKind(kind),
		})
		if err != nil {
			return nil, err
		}
		return cred, nil
	}
}
