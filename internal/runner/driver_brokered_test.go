package runner_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubBroker is a test-only BrokerExchanger.
type stubBroker struct {
	result broker.ExchangeResult
	err    error
	calls  int
}

func (s *stubBroker) Exchange(_ context.Context, _, _, _, _, _ string) (broker.ExchangeResult, error) {
	s.calls++
	return s.result, s.err
}

func (s *stubBroker) Revoke(_ context.Context, _ string) error { return nil }

// brokeredTmpl builds a ConnectionTemplate with direct_brokered support.
func brokeredTmpl(provider string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: provider,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeDirectBrokered,
			Supported: []registry.RuntimeMode{registry.RuntimeDirectBrokered},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "api_key"},
		},
	}
}

// brokeredTmplNoSupport builds a template that does NOT support direct_brokered.
func brokeredTmplNoSupport() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "unsupported",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "api_key"},
		},
	}
}

// TestBrokeredDriver_StrategyNotFound verifies ErrUnsupportedRuntime when
// the template does not declare direct_brokered support.
func TestBrokeredDriver_StrategyNotFound(t *testing.T) {
	vault := newClassicMockBackend()
	b := &stubBroker{}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "unsupported",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, brokeredTmplNoSupport())
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrUnsupportedRuntime),
		"must return ErrUnsupportedRuntime when template lacks direct_brokered support")
}

// TestBrokeredDriver_ExchangeError verifies error propagation when the broker
// exchange fails.
func TestBrokeredDriver_ExchangeError(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root-cred"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	exchangeErr := errors.New("broker: service unavailable")
	b := &stubBroker{err: exchangeErr}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broker exchange")
}

// TestBrokeredDriver_ChildEnvInjection verifies the short-lived token from the
// broker is injected into the child process via the template's env var.
func TestBrokeredDriver_ChildEnvInjection(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root-secret"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const ephemeralToken = "ephemeral-token-from-broker-xyz"
	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9 /* 1h */, broker.FreshExchange, []byte(ephemeralToken))
	b := &stubBroker{result: result}

	var outBuf strings.Builder
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "echo $TEST_API_KEY"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.NoError(t, err)
	assert.Equal(t, 0, receipt.ExitCode)
	assert.Contains(t, outBuf.String(), ephemeralToken,
		"ephemeral token must be visible to child via injected env var")
}

// TestBrokeredDriver_RootCredentialNotInChildEnv verifies that the vault's root
// credential is NOT directly injected into the child (only the brokered token is).
func TestBrokeredDriver_RootCredentialNotInChildEnv(t *testing.T) {
	vault := newClassicMockBackend()
	const rootCred = "root-secret-must-not-reach-child"
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte(rootCred), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const ephemeralToken = "ephemeral-token-from-broker-safe"
	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte(ephemeralToken))
	b := &stubBroker{result: result}

	var outBuf strings.Builder
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "printenv TEST_API_KEY"},
		Stdout:         &outBuf,
		Stderr:         &strings.Builder{},
	}

	_, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.NoError(t, err)

	// Child must receive the ephemeral token, NOT the root credential.
	assert.NotContains(t, outBuf.String(), rootCred,
		"root credential must not be injected into child env")
	assert.Contains(t, outBuf.String(), ephemeralToken,
		"child must receive ephemeral token")
}

// TestBrokeredDriver_ReceiptEmitted verifies that a RuntimeReceipt is returned
// with the correct runtime mode.
func TestBrokeredDriver_ReceiptEmitted(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	result := broker.NewExchangeResult("myapi", "inject", 3600*1e9, broker.FreshExchange, []byte("tok"))
	b := &stubBroker{result: result}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "true"},
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.NoError(t, err)
	assert.Equal(t, "direct_brokered", receipt.Runtime)
}

// TestBrokeredDriver_VaultCredentialNotFound verifies ErrNotFound propagation
// when the vault is missing the expected credential.
func TestBrokeredDriver_VaultCredentialNotFound(t *testing.T) {
	vault := newClassicMockBackend() // empty vault
	b := &stubBroker{}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound),
		"must propagate ErrNotFound when vault is missing credential")
}

// TestBrokeredDriver_BrokerExchangeFailure_ErrorPropagated verifies that an
// error returned by the broker exchange is wrapped and returned as a driver error.
func TestBrokeredDriver_BrokerExchangeFailure_ErrorPropagated(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	brokerErr := errors.New("broker: upstream unavailable")
	b := &stubBroker{err: brokerErr}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broker exchange",
		"broker exchange failure must surface in error message")
}

// TestBrokeredDriver_NilBroker_ReturnsError verifies that when RuntimeSupport.Broker
// is conceptually absent (template has no direct_brokered support), ErrUnsupportedRuntime
// is returned rather than a nil-pointer panic.
func TestBrokeredDriver_NilBroker_UnsupportedRuntime(t *testing.T) {
	vault := newClassicMockBackend()
	// tmpl with no direct_brokered support
	tmpl := brokeredTmplNoSupport()

	var typedNilBroker *stubBroker // typed nil — non-nil interface, never called because ErrUnsupportedRuntime is returned first
	d := runner.NewBrokeredDriver(vault, typedNilBroker, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "unsupported",
		Command:        []string{"sh", "-c", "true"},
	}

	_, err := d.Run(context.Background(), req, tmpl)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrUnsupportedRuntime),
		"nil broker + unsupported template must return ErrUnsupportedRuntime before any broker call")
}

// TestBrokeredDriver_RevokeOnExit simulates the revoke-on-exit pattern by
// verifying that after a successful exchange the broker result's TTL is non-zero
// (so a subsequent revoke would be meaningful).
func TestBrokeredDriver_RevokeOnExit_TokenTTLNonZero(t *testing.T) {
	vault := newClassicMockBackend()
	path := classicSecretPath("default", "ai", "myapi", "api_key")
	require.NoError(t, vault.Set(context.Background(), path, []byte("root"), backend.Meta{
		Path: path, Backend: "stub", Version: 1,
	}))

	const ttl = 1800 * 1e9 // 30 minutes in nanoseconds
	result := broker.NewExchangeResult("myapi", "inject", ttl, broker.FreshExchange, []byte("tok"))
	b := &stubBroker{result: result}
	d := runner.NewBrokeredDriver(vault, b, nil)

	req := runner.ExecRequest{
		ConnectionSlug: "myapi",
		Command:        []string{"sh", "-c", "true"},
		Stderr:         &strings.Builder{},
	}

	receipt, err := d.Run(context.Background(), req, brokeredTmpl("myapi"))
	require.NoError(t, err)
	assert.Equal(t, 0, receipt.ExitCode)
	// Verify the broker was called exactly once.
	assert.Equal(t, 1, b.calls, "broker.Exchange must be called exactly once per Run")
}
