package cli_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/stretchr/testify/assert"
)

func TestExitCodes_Values(t *testing.T) {
	assert.Equal(t, 0, exitcode.OK)
	assert.Equal(t, 1, exitcode.UserError)
	assert.Equal(t, 2, exitcode.SecurityBlock)
	assert.Equal(t, 3, exitcode.Missing)
	assert.Equal(t, 4, exitcode.BackendUnavailable)
	assert.Equal(t, 5, exitcode.OperationFailed)
	assert.Equal(t, 5, exitcode.RuntimeNotAvailable)
	assert.Equal(t, 7, exitcode.BootstrapMissing)
	assert.Equal(t, 8, exitcode.InsecureArgv)
}

func TestExitCodes_Unique(t *testing.T) {
	// Only test the primary (non-alias) codes for uniqueness.
	all := []int{
		exitcode.OK,
		exitcode.UserError,
		exitcode.SecurityBlock,
		exitcode.Missing,
		exitcode.BackendUnavailable,
		exitcode.OperationFailed,
		exitcode.BootstrapMissing,
		exitcode.InsecureArgv,
	}
	seen := map[int]bool{}
	for _, code := range all {
		assert.False(t, seen[code], "duplicate exit code: %d", code)
		seen[code] = true
	}
}
