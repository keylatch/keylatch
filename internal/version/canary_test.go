package version_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canary = "KEYLATCH_CANARY_"

func TestString_NoCanary(t *testing.T) {
	s := version.String()
	assert.False(t, strings.Contains(s, canary),
		"version.String() must not contain %q sentinel, got: %q", canary, s)
}

func TestJSON_NoCanary(t *testing.T) {
	v := version.JSON()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(b), canary),
		"marshalled version.JSON() must not contain %q sentinel, got: %q", canary, string(b))
}
