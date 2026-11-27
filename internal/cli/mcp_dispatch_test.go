package cli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
)

type countingDriver struct{ calls int }

func (d *countingDriver) Run(context.Context, runner.ExecRequest, registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	d.calls++
	return runner.RuntimeReceipt{PolicyDecision: "allowed"}, nil
}

type captureEmitter struct{ events []audit.Event }

func (c *captureEmitter) Emit(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}

// An agent's keylatch_run is decided by connection policy: with no policy the
// request is denied before a driver starts, and the refusal is audited.
func TestMCPDispatchDeniesAgentWithoutPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(enforce.SetDefault(nil))
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv))
	drv := &countingDriver{}
	em := &captureEmitter{}
	dr := mcpDispatchRunner(llmcontext.DefaultLookup, em, map[string]runner.Driver{
		string(runtime.RuntimeGatewayTyped): drv,
	})

	_, err := dr.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug:       "anthropic",
		Command:              []string{"sh", "-c", "true"},
		ExtraAllowedPrefixes: []string{"sh"},
		Runtime:              string(runtime.RuntimeGatewayTyped),
		Caller:               callerkind.Agent,
	})

	var denied *runner.PolicyDeniedError
	require.True(t, errors.As(err, &denied), "err = %v", err)
	assert.Zero(t, drv.calls, "a denied run must not reach a driver")
	require.Len(t, em.events, 1)
	assert.Equal(t, "policy_denied", em.events[0].Extra["decision"])
	assert.Equal(t, string(callerkind.Agent), em.events[0].Extra["caller_kind"])
}
