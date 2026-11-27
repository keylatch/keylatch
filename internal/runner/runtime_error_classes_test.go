package runner_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRuntimeError_ExitCodeMatrix(t *testing.T) {
	cases := map[string]int{
		"UsageError":          1,
		"SecurityBlock":       2,
		"PolicyDeny":          3,
		"ApprovalRequired":    4,
		"BackendUnavailable":  4,
		"RuntimeNotAvailable": 5,
		"GatewayNotRunning":   5,
		"SecretNotFound":      6,
		"BootstrapMissing":    7,
		"InsecureArgv":        8,
		"InternalError":       9,
		"SomethingNew":        5,
	}
	for class, want := range cases {
		e := runner.NewRuntimeError(class, "p", "m", "r", "", nil)
		assert.Equal(t, want, e.ExitCode, class)
	}
}

func TestRuntimeError_FormatAndUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := runner.NewRuntimeError("PolicyDeny", "openai", "gateway_typed", "denied by rule", "", cause)
	assert.Equal(t, "PolicyDeny: openai + gateway_typed: denied by rule", e.Error())
	assert.ErrorIs(t, e, cause)

	e.Fix = "Try: keylatch policy allow"
	assert.Equal(t, "PolicyDeny: openai + gateway_typed: denied by rule. Try: keylatch policy allow", e.Error())
}

func TestRuntimeError_Constructors(t *testing.T) {
	cause := errors.New("underlying")
	cases := []struct {
		err       *runner.RuntimeError
		class     string
		exit      int
		reason    string
		fixSubstr string
	}{
		{runner.ErrSecretNotFound("anthropic", "direct_brokered", cause), "SecretNotFound", 6, "no credential found", "keylatch connect anthropic"},
		{runner.ErrTokenMintFailed("openai", "gateway_typed", cause), "RuntimeNotAvailable", 5, "failed to mint session token", "keylatch doctor"},
		{runner.ErrBrokerExchange("github", "direct_brokered", cause), "RuntimeNotAvailable", 5, "broker exchange failed", "keylatch doctor"},
	}
	for _, tc := range cases {
		require.NotNil(t, tc.err)
		assert.Equal(t, tc.class, tc.err.Class)
		assert.Equal(t, tc.exit, tc.err.ExitCode)
		assert.Contains(t, tc.err.Error(), tc.reason)
		assert.Contains(t, tc.err.Fix, tc.fixSubstr)
		assert.ErrorIs(t, tc.err, cause)
	}
}
