package main

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
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
	category := tmpl.Category
	if category == "" {
		category = "ai"
	}
	ctx = audit.WithEmitter(ctx, r.log)
	return vault.Get(ctx, "default/"+category+"/"+connection+"/"+field, r.cfg, r.env)
}

// newPlaceholders opens the audit log and builds the manager that serves tier
// D3. The returned function releases the audit log.
func newPlaceholders(env llmcontext.Lookup) (*placeholder.Manager, func(), error) {
	logger, closeLog, err := cli.OpenAuditLogger()
	if err != nil {
		return nil, nil, fmt.Errorf("audit log: %w", err)
	}
	cfg := config.Default()
	if loaded, err := config.Load(paths.Config(env)); err == nil {
		cfg = loaded
	}
	em := audit.AsEmitter(logger)
	mgr, err := placeholder.NewManager(placeholder.Config{Resolver: vaultResolver{cfg: cfg, env: env, log: em}, Audit: em})
	if err != nil {
		closeLog()
		return nil, nil, err
	}
	return mgr, func() { mgr.Close(); closeLog() }, nil
}
