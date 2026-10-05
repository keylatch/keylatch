package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/registry"
)

// ErrModeUnavailable is returned by WithManifestGuard when a runtime mode is
// gated out of the current build's manifest. There is no fallback once this
// is returned — the caller must not retry with a different driver.
var ErrModeUnavailable = errors.New("runner: runtime mode is not available in this build")

// manifestGuardDriver wraps a Driver with a manifest support check.
type manifestGuardDriver struct {
	inner Driver
	id    string
	m     manifest.Manifest
}

// WithManifestGuard wraps inner so it only runs when m marks id Supported.
// This is the sole containment point for runtime modes excluded from the
// current milestone (e.g. direct_brokered, gateway_proxy,
// direct_classic_sandboxed): inner is never invoked, and no fallback
// path exists once ErrModeUnavailable is returned.
func WithManifestGuard(inner Driver, m manifest.Manifest, id string) Driver {
	return &manifestGuardDriver{inner: inner, id: id, m: m}
}

func (g *manifestGuardDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	if !g.m.Enabled(g.id) {
		return RuntimeReceipt{
			Runtime:        req.Runtime,
			PolicyDecision: "manifest_unavailable",
		}, fmt.Errorf("%s: %w", g.id, ErrModeUnavailable)
	}
	return g.inner.Run(ctx, req, tmpl)
}
