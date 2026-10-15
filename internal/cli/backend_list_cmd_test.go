package cli_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/cli"
)

func TestBackendListJSONMatchesTierPolicy(t *testing.T) {
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"backend", "list", "--json"})
	require.NoError(t, root.Execute())

	var rows []struct {
		ID   string `json:"id"`
		Tier string `json:"tier"`
		Note string `json:"note"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &rows))
	require.Len(t, rows, 14)

	tiers := map[string]string{}
	for _, r := range rows {
		tiers[r.ID] = r.Tier
		assert.NotEmpty(t, r.Note, r.ID)
	}
	want := map[string]string{
		"bw": "supported", "op": "supported", "file": "supported",
		"vault": "community", "awssm": "community", "gcpsm": "community", "azurekv": "community",
		"doppler": "community", "infisical": "community", "opconnect": "community",
		"keychain": "deprecated", "keeper": "deprecated", "lastpass": "deprecated", "proton-pass": "deprecated",
	}
	assert.Equal(t, want, tiers)
}

func TestBackendListTable(t *testing.T) {
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"backend", "list"})
	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "TIER")
	assert.Contains(t, out.String(), "deprecated")
}
