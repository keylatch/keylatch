package runner_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return r.err
}

func auditedRunner(em audit.Emitter, guard runner.GuardFunc) runner.DispatchRunner {
	return runner.DispatchRunner{
		Guard: guard,
		Audit: em,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeGatewayTyped): &stubDriver{receipt: runner.RuntimeReceipt{ExitCode: 3, PolicyDecision: "allowed"}},
		},
	}
}

// Every Run writes exactly one run event, whether it is allowed or refused at
// any stage, and the event holds names and counters only.
func TestEveryBrokeredActionAudited(t *testing.T) {
	const canary = "sk-canary-0123456789abcdef"
	allowed := runner.ExecRequest{
		ConnectionSlug:       "anthropic",
		Command:              []string{"sh", "-c", canary},
		ExtraAllowedPrefixes: []string{"sh"},
		Runtime:              string(runtime.RuntimeGatewayTyped),
		CallerKind:           "agent",
	}
	cases := []struct {
		name     string
		req      runner.ExecRequest
		guard    runner.GuardFunc
		wantErr  bool
		decision string
	}{
		{"allowed", allowed, nil, false, "allowed"},
		{"guard denied", allowed, func(runtime.RuntimeMode, string) bool { return true }, true, "guard_denied"},
		{"unknown provider", func() runner.ExecRequest { r := allowed; r.ConnectionSlug = "no-such-provider"; return r }(), nil, true, "provider_not_found"},
		{"command not allowed", func() runner.ExecRequest {
			r := allowed
			r.ExtraAllowedPrefixes = nil
			r.Command = []string{"/bin/evil"}
			return r
		}(), nil, true, "command_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			em := &recordingEmitter{}
			_, err := auditedRunner(em, tc.guard).Run(context.Background(), tc.req)
			assert.Equal(t, tc.wantErr, err != nil, "err = %v", err)

			require.Len(t, em.events, 1, "each Run writes exactly one event")
			ev := em.events[0]
			assert.Equal(t, audit.ActionRun, ev.Action)
			assert.Equal(t, tc.decision, ev.Extra["decision"])
			if tc.req.CallerKind != "" {
				assert.Equal(t, tc.req.CallerKind, ev.Extra["caller_kind"])
			}
			for k, v := range ev.Extra {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, canary, "field %q carries a value", k)
				}
			}
			assert.False(t, strings.Contains(ev.Path+ev.Accessor, canary))
		})
	}
}

func TestRunRefusedWhenAuditCannotRecord(t *testing.T) {
	dr := auditedRunner(unavailableEmitter{}, nil)
	_, err := dr.Run(context.Background(), runner.ExecRequest{ConnectionSlug: "anthropic", Command: []string{"sh"}, ExtraAllowedPrefixes: []string{"sh"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, audit.ErrUnavailable))
}

type unavailableEmitter struct{}

func (unavailableEmitter) Emit(context.Context, audit.Event) error { return audit.ErrUnavailable }
func (unavailableEmitter) Ready() error                            { return audit.ErrUnavailable }
