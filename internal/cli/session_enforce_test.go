package cli_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireRawCredentialOptIn_GatewayModesUnaffected(t *testing.T) {
	t.Parallel()
	assert.NoError(t, cli.RequireRawCredentialOptIn(false, false))
}

func TestRequireRawCredentialOptIn_RawExposureFailsClosed(t *testing.T) {
	t.Parallel()
	err := cli.RequireRawCredentialOptIn(true, false)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "allow_unverified_session", "refusal must not advertise the opt-out")
	assert.NotContains(t, err.Error(), "KEYLATCH_", "refusal must not name any environment variable")
}

func TestRequireRawCredentialOptIn_ConfigOptIn(t *testing.T) {
	t.Parallel()
	assert.NoError(t, cli.RequireRawCredentialOptIn(true, true))
}
