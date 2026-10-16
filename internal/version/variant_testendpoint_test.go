//go:build mint_test_endpoint

package version_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestEndpointBuildSaysSo(t *testing.T) {
	assert.True(t, strings.HasSuffix(version.String(), " testendpoint"))
	b, err := json.Marshal(version.JSON())
	require.NoError(t, err)
	assert.Contains(t, string(b), `"Variant":"testendpoint"`)
}
