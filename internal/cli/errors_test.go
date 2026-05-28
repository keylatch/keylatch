package cli_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExitCodeMatrix asserts that every CLIError constructor produces an error
// whose Code matches the declared exit-code for that class (EPIC-02 Task 2).
func TestExitCodeMatrix(t *testing.T) {
	t.Parallel()

	type entry struct {
		name     string
		err      *cli.CLIError
		wantCode int
		wantCls  string
	}

	cases := []entry{
		{"UsageError", cli.NewUsageError("bad flag"), 1, "UsageError"},
		{"SecurityBlock", cli.NewSecurityBlock("llm blocked"), 2, "SecurityBlock"},
		{"PolicyDeny", cli.NewPolicyDeny("denied"), 3, "PolicyDeny"},
		{"ApprovalRequired", cli.NewApprovalRequired("needs approval"), 4, "ApprovalRequired"},
		{"RuntimeNotAvailable", cli.NewRuntimeNotAvailable("no mode"), 5, "RuntimeNotAvailable"},
		{"SecretNotFound", cli.NewSecretNotFound("key missing"), 6, "SecretNotFound"},
		{"BootstrapMissing", cli.NewBootstrapMissing("not bootstrapped"), 7, "BootstrapMissing"},
		{"BackendUnavailable", cli.NewBackendUnavailable("vault down"), 4, "BackendUnavailable"},
		{"InternalError", cli.NewInternalError("unexpected"), 9, "InternalError"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NotNil(t, tc.err)
			assert.Equal(t, tc.wantCode, tc.err.Code,
				"exit code mismatch for class %q", tc.wantCls)
			assert.Equal(t, tc.wantCls, tc.err.Class,
				"class mismatch for %q", tc.name)
			assert.NotEmpty(t, tc.err.Message, "Message must not be empty")

			// error interface must include class and code.
			errStr := tc.err.Error()
			assert.Contains(t, errStr, tc.wantCls)

			// Stderr output must include the class.
			stderrStr := tc.err.Stderr()
			assert.True(t, strings.HasSuffix(stderrStr, "\n"),
				"Stderr() must end with newline")
			assert.Contains(t, stderrStr, tc.wantCls)
		})
	}
}

// TestCLIError_ImplementsError verifies that *CLIError satisfies the error interface.
func TestCLIError_ImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = cli.NewUsageError("test")
}
