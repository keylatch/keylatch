package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitNamespaceFlags(t *testing.T) {
	ns, mapping, err := splitNamespaceFlags([]string{"a=B/c", "plain", " d = E "})
	require.NoError(t, err)
	assert.Equal(t, "plain", ns)
	assert.Equal(t, map[string]string{"a": "B/c", "d": "E"}, mapping)

	for _, bad := range []string{"=x", "x=", " = "} {
		_, _, err = splitNamespaceFlags([]string{bad})
		assert.Error(t, err, bad)
	}
	ns, mapping, err = splitNamespaceFlags(nil)
	require.NoError(t, err)
	assert.Empty(t, ns)
	assert.Nil(t, mapping)
}
