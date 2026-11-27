//go:build !mint_test_endpoint && !sync_test_endpoint

package version_test

import (
	"encoding/json"
	"testing"

	"github.com/keylatch/keylatch/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultBuildSaysNothingOfAVariant(t *testing.T) {
	assert.NotContains(t, version.String(), "testendpoint")
	b, err := json.Marshal(version.JSON())
	require.NoError(t, err)
	assert.NotContains(t, string(b), "Variant")
}
