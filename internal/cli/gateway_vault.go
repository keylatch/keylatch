package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/keylatch/keylatch/internal/vault"
)

// gatewayVaultReader adapts the configured vault backend to gateway.VaultReader.
//
// Reads go through vault.Get so every credential read by the gateway emits an
// ActionRead audit event (the handler attaches the audit emitter to ctx).
//
// The gateway process is started by
// `gateway up`, which is a human-operated command; the credential is injected
// into the upstream request only and never returned to the caller.
type gatewayVaultReader struct {
	cfg config.Config
	env llmcontext.Lookup
	// read and resolver are test seams; nil selects vault.Get and the real exec runner.
	read     func(ctx context.Context, path string) ([]byte, error)
	resolver func(ctx context.Context, ref string) ([]byte, error)
}

var _ gateway.VaultReader = (*gatewayVaultReader)(nil)

// errGatewayRefResolve carries no ref, stderr or plaintext: resolver errors can echo them.
var errGatewayRefResolve = errors.New("gateway: resolve external store reference failed")

func (r *gatewayVaultReader) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	read := r.read
	if read == nil {
		read = func(ctx context.Context, p string) ([]byte, error) {
			return vault.Get(ctx, p, r.cfg, r.env)
		}
	}
	value, err := read(ctx, path)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	// Fields stored via --provider-ref hold a URI, not the credential.
	if store.IsProviderRefURI(value) {
		resolve := r.resolver
		if resolve == nil {
			resolve = storeNewResolver().Resolve
		}
		resolved, rerr := resolve(ctx, string(value))
		clear(value)
		if rerr != nil {
			return nil, backend.Meta{}, errGatewayRefResolve
		}
		value = resolved
	}
	return value, backend.Meta{Path: path}, nil
}

// newGatewayVaultReader resolves the configured backend once so that a
// misconfigured or unavailable vault fails `gateway up` at startup instead of
// letting every request reach the upstream without a credential.
func newGatewayVaultReader(ctx context.Context, cfg config.Config, env llmcontext.Lookup) (gateway.VaultReader, error) {
	if _, err := dispatch.Select(ctx, cfg, env); err != nil {
		return nil, fmt.Errorf("open vault backend: %w", err)
	}
	return &gatewayVaultReader{cfg: cfg, env: env}, nil
}
