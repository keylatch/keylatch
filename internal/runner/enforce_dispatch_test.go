package runner_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingDriver struct {
	called bool
	got    runner.ExecRequest
}

func (d *recordingDriver) Run(_ context.Context, req runner.ExecRequest, _ registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	d.called = true
	d.got = req
	return runner.RuntimeReceipt{}, nil
}

func enforcedRunner(drv runner.Driver, fn func(context.Context, enforce.Request) enforce.Decision) runner.DispatchRunner {
	return runner.DispatchRunner{
		Enforce: fn,
		Drivers: map[string]runner.Driver{string(runtime.RuntimeGatewayTyped): drv},
	}
}

func enforcedRequest() runner.ExecRequest {
	return runner.ExecRequest{
		ConnectionSlug:       "anthropic",
		Command:              []string{"sh", "-c", "true"},
		ExtraAllowedPrefixes: []string{"sh"},
		Runtime:              string(runtime.RuntimeGatewayTyped),
		Caller:               callerkind.Agent,
		Stderr:               &strings.Builder{},
	}
}

func TestDispatchAsksPolicyBeforeTheDriver(t *testing.T) {
	var asked enforce.Request
	drv := &recordingDriver{}
	dr := enforcedRunner(drv, func(_ context.Context, r enforce.Request) enforce.Decision {
		asked = r
		return enforce.Decision{Reason: "no policy for anthropic: run `keylatch policy init`"}
	})

	receipt, err := dr.Run(context.Background(), enforcedRequest())

	var denied *runner.PolicyDeniedError
	require.ErrorAs(t, err, &denied)
	assert.ErrorIs(t, err, runner.ErrPolicyDeny)
	assert.False(t, drv.called, "the driver ran although policy denied the request")
	assert.Equal(t, "policy_denied", receipt.PolicyDecision)
	assert.Equal(t, enforce.Request{
		Connection: "anthropic",
		Action:     "inject",
		Runtime:    string(runtime.RuntimeGatewayTyped),
		Caller:     callerkind.Agent,
		Command:    []string{"sh", "-c", "true"},
	}, asked)
}

func TestDispatchTreatsPendingApprovalAsADeny(t *testing.T) {
	drv := &recordingDriver{}
	dr := enforcedRunner(drv, func(context.Context, enforce.Request) enforce.Decision {
		return enforce.Decision{Allow: true, ApprovalRequired: true}
	})
	_, err := dr.Run(context.Background(), enforcedRequest())
	assert.ErrorIs(t, err, runner.ErrApprovalRequired)
	assert.False(t, drv.called)
}

func TestDispatchAppliesPolicyMaxTTL(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"unset becomes the cap", 0, 10 * time.Minute},
		{"longer is cut to the cap", time.Hour, 10 * time.Minute},
		{"shorter is kept", time.Minute, time.Minute},
	} {
		drv := &recordingDriver{}
		dr := enforcedRunner(drv, func(context.Context, enforce.Request) enforce.Decision {
			return enforce.Decision{Allow: true, MaxTTL: 10 * time.Minute}
		})
		req := enforcedRequest()
		req.TTL = tc.ttl
		_, err := dr.Run(context.Background(), req)
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.want, drv.got.TTL, tc.name)
	}
}

func TestDispatchClassifiesAnUnlabelledCaller(t *testing.T) {
	var asked enforce.Request
	dr := enforcedRunner(&recordingDriver{}, func(_ context.Context, r enforce.Request) enforce.Decision {
		asked = r
		return enforce.Decision{Allow: true}
	})
	req := enforcedRequest()
	req.Caller = ""
	_, err := dr.Run(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, asked.Caller, "a request with no caller kind reached policy unclassified")
}

// A run token records who asked for it, and an agent's token is an LLM-session
// token so the gateway's agent route restrictions apply to it.
func TestRunTokenCarriesCallerKind(t *testing.T) {
	for _, tc := range []struct {
		caller callerkind.Kind
		llm    bool
	}{
		{callerkind.Agent, true},
		{callerkind.Host, false},
		{callerkind.Human, false},
		{callerkind.Service, false},
	} {
		t.Run(string(tc.caller), func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "tokens.json")
			srv := &mockTypedServer{addr: "127.0.0.1:7878", running: true}
			d := runner.NewGatewayTypedDriver(srv, newSigningKey(t), storePath)

			req := enforcedRequest()
			req.Caller = tc.caller
			req.Runtime = ""
			_, err := d.Run(context.Background(), req, gatewayTypedTmpl("anthropic"))
			if err != nil && errors.Is(err, runner.ErrGatewayNotRunning) {
				t.Fatalf("gateway reported down: %v", err)
			}

			toks, err := token.List(token.ListOpts{IncludeExpired: true, IncludeRevoked: true}, storePath)
			require.NoError(t, err)
			require.Len(t, toks, 1)
			assert.Equal(t, tc.caller, toks[0].CallerKind)
			assert.Equal(t, tc.llm, toks[0].LLMSession)
		})
	}
}
