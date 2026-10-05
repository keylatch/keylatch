package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScopeCmd_TableOutput proves `keylatch scope` is a real consumer of the
// support manifest — it loads internal/manifest.Current() and prints entries.
func TestScopeCmd_TableOutput(t *testing.T) {
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"scope"})
	require.NoError(t, root.Execute())

	got := out.String()
	assert.Contains(t, got, "op")
	assert.Contains(t, got, "supported")
	assert.Contains(t, got, "gateway_proxy")
	assert.Contains(t, got, "unavailable")
}

func TestScopeCmd_JSONOutput(t *testing.T) {
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"scope", "--json"})
	require.NoError(t, root.Execute())

	var parsed struct {
		Entries []struct {
			ID     string
			Status string
		}
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(out.String())).Decode(&parsed))
	assert.NotEmpty(t, parsed.Entries)
}
