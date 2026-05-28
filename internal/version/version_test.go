package version_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestString_DefaultFormat(t *testing.T) {
	s := version.String()
	assert.True(t, strings.HasPrefix(s, "keylatch "),
		"String() must start with 'keylatch ', got: %q", s)
	assert.Contains(t, s, "built ", "String() must contain 'built '")
}

func TestString_ContainsDefaultValues(t *testing.T) {
	// In test builds ldflags are not set, so defaults apply.
	s := version.String()
	assert.Contains(t, s, "dev")
	assert.Contains(t, s, "unknown")
}

func TestJSON_FieldPresence(t *testing.T) {
	v := version.JSON()
	b, err := json.Marshal(v)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(b, &m))

	_, hasVersion := m["Version"]
	_, hasCommit := m["Commit"]
	_, hasBuildDate := m["BuildDate"]

	assert.True(t, hasVersion, "JSON output must have 'Version' field")
	assert.True(t, hasCommit, "JSON output must have 'Commit' field")
	assert.True(t, hasBuildDate, "JSON output must have 'BuildDate' field")
}

func TestJSON_DefaultValues(t *testing.T) {
	v := version.JSON()
	b, err := json.Marshal(v)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(b, &m))

	assert.Equal(t, "1.0.0-dev", m["Version"])
	assert.Equal(t, "unknown", m["Commit"])
	assert.Equal(t, "unknown", m["BuildDate"])
}
