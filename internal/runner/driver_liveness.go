package runner

import (
	"context"
	"errors"

	"github.com/keylatch/keylatch/internal/registry"
)

// ErrProxyNotRunning is returned when the gateway_proxy driver cannot reach the
// proxy server.
var ErrProxyNotRunning = errors.New("runner: proxy is not running — run 'keylatch proxy up' first")

// livenessGuardDriver wraps a Driver with a pre-flight liveness check.
// If check() returns false, the wrapped driver is not called and errNotRunning
// is returned instead.
type livenessGuardDriver struct {
	inner         Driver
	check         func() bool
	errNotRunning error
}

// WithLivenessGuard wraps inner with a liveness check. If check() returns false,
// errNotRunning is returned without calling inner. This is used to add
// not-running guards to drivers whose servers are checked externally (e.g. proxy).
func WithLivenessGuard(inner Driver, check func() bool, errNotRunning error) Driver {
	return &livenessGuardDriver{
		inner:         inner,
		check:         check,
		errNotRunning: errNotRunning,
	}
}

func (g *livenessGuardDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	if !g.check() {
		return RuntimeReceipt{
			Runtime:        req.Runtime,
			PolicyDecision: "not_running",
		}, g.errNotRunning
	}
	return g.inner.Run(ctx, req, tmpl)
}
