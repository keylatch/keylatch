package runner_test

import (
	"reflect"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
)

// TestNoBlocklistField verifies that Connection has no blocklist/denylist field.
func TestNoBlocklistField(t *testing.T) {
	tp := reflect.TypeOf(runner.Connection{})
	blocklisted := []string{"Blocklist", "DenyList", "Deny", "Block", "Denied"}
	for i := 0; i < tp.NumField(); i++ {
		fieldName := tp.Field(i).Name
		for _, forbidden := range blocklisted {
			assert.NotEqual(t, forbidden, fieldName,
				"Connection must not have a %q field (allowlist-only)", forbidden)
		}
	}
}

// TestErrSentinelsDefined verifies the sentinel errors are exported and non-nil.
func TestErrSentinelsDefined(t *testing.T) {
	assert.NotNil(t, runner.ErrCommandNotAllowed)
	assert.NotNil(t, runner.ErrUnknownRuntime)
	assert.NotNil(t, runner.ErrGuardDenied)
}

// TestExecRequestZeroValue verifies ExecRequest can be constructed without panics.
func TestExecRequestZeroValue(t *testing.T) {
	var req runner.ExecRequest
	assert.Empty(t, req.ConnectionSlug)
	assert.Nil(t, req.Command)
}

// TestRuntimeReceiptZeroValue verifies RuntimeReceipt is value-free by construction.
func TestRuntimeReceiptZeroValue(t *testing.T) {
	var r runner.RuntimeReceipt
	assert.Empty(t, r.Runtime)
	assert.Empty(t, r.Provider)
}
