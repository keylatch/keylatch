package runner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

// spyDriver records whether Run was ever invoked.
type spyDriver struct{ called bool }

func (d *spyDriver) Run(context.Context, runner.ExecRequest, registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	d.called = true
	return runner.RuntimeReceipt{}, nil
}

// TestSecurityRegression_DirectRuntimesUnreachable verifies that
// direct_brokered, gateway_proxy, and direct_classic_sandboxed are all
// gated Unavailable in the support manifest, and that WithManifestGuard actually
// refuses to invoke the wrapped driver for a gated mode — the real
// production wiring (internal/cli/root.go) uses this exact guard, so any
// CLI/API/MCP caller is denied before a direct secret-injection mode can
// run, with no fallback path.
func TestSecurityRegression_DirectRuntimesUnreachable(t *testing.T) {
	m := manifest.Current()
	for _, id := range []string{"direct_brokered", "gateway_proxy", "direct_classic_sandboxed"} {
		if m.Enabled(id) {
			t.Errorf("manifest: %q must remain Unavailable", id)
		}
	}

	for _, id := range []string{"direct_brokered", "gateway_proxy", "direct_classic_sandboxed"} {
		spy := &spyDriver{}
		guarded := runner.WithManifestGuard(spy, m, id)
		_, err := guarded.Run(context.Background(), runner.ExecRequest{Runtime: id}, registry.ConnectionTemplate{})
		if err == nil {
			t.Errorf("%s: expected ErrModeUnavailable, got nil", id)
		}
		if !errors.Is(err, runner.ErrModeUnavailable) {
			t.Errorf("%s: expected ErrModeUnavailable, got: %v", id, err)
		}
		if spy.called {
			t.Errorf("%s: wrapped driver was invoked despite being gated unavailable", id)
		}
	}
}

// TestSecurityRegression_ManifestGuardAllowsSupportedMode verifies the
// guard does not interfere with a Supported mode (gateway_typed).
func TestSecurityRegression_ManifestGuardAllowsSupportedMode(t *testing.T) {
	spy := &spyDriver{}
	guarded := runner.WithManifestGuard(spy, manifest.Current(), "gateway_typed")
	if _, err := guarded.Run(context.Background(), runner.ExecRequest{}, registry.ConnectionTemplate{}); err != nil {
		t.Fatalf("unexpected error for supported mode: %v", err)
	}
	if !spy.called {
		t.Error("expected wrapped driver to run for a supported mode")
	}
}
