package cli

import (
	"bytes"
	"testing"

	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func localOnlyTestCmd(args ...string) *cobra.Command {
	c := &cobra.Command{Use: "connect"}
	c.Flags().String("class", "", "")
	c.Flags().StringArray("local-only", nil, "")
	_ = c.ParseFlags(args)
	return c
}

var appSecretsTemplate = registry.ConnectionTemplate{
	Provider: "app-local",
	SecretFields: []registry.SecretField{
		{Name: "JWT_SECRET", EnvVar: "JWT_SECRET"},
		{Name: "API_KEY", EnvVar: "API_KEY"},
	},
}

func TestParseLocalOnlyFlags(t *testing.T) {
	class, modes, err := parseLocalOnlyFlags(localOnlyTestCmd("--class", "dev", "--local-only", "JWT_SECRET=ephemeral"))
	require.NoError(t, err)
	assert.Equal(t, localonly.ClassDev, class)
	assert.Equal(t, localonly.Ephemeral, modes["JWT_SECRET"])
}

func TestParseLocalOnlyFlagsRejects(t *testing.T) {
	for _, args := range [][]string{
		{"--class", "prod", "--local-only", "JWT_SECRET=ephemeral"},
		{"--local-only", "JWT_SECRET=ephemeral"},
		{"--class", "dev", "--local-only", "JWT_SECRET"},
		{"--class", "dev", "--local-only", "JWT_SECRET=weird"},
		{"--class", "staging"},
	} {
		_, _, err := parseLocalOnlyFlags(localOnlyTestCmd(args...))
		assert.Error(t, err, "%v", args)
	}
}

func TestSuggestLocalOnlyNeverAppliesWithoutConfirmation(t *testing.T) {
	var stderr bytes.Buffer
	c := localOnlyTestCmd()
	c.SetErr(&stderr)
	modes := map[string]localonly.Mode{}

	suggestLocalOnly(c, appSecretsTemplate, localonly.ClassDev, modes, nil)
	assert.Empty(t, modes)
	assert.Contains(t, stderr.String(), "JWT_SECRET")
	assert.NotContains(t, stderr.String(), "API_KEY")
}

func TestSuggestLocalOnlyAppliesOnHumanConfirmation(t *testing.T) {
	modes := map[string]localonly.Mode{}
	suggestLocalOnly(localOnlyTestCmd(), appSecretsTemplate, localonly.ClassTest, modes, func(string) bool { return true })
	assert.Equal(t, map[string]localonly.Mode{"JWT_SECRET": localonly.Ephemeral}, modes)

	declined := map[string]localonly.Mode{}
	suggestLocalOnly(localOnlyTestCmd(), appSecretsTemplate, localonly.ClassDev, declined, func(string) bool { return false })
	assert.Empty(t, declined)
}

func TestSuggestLocalOnlySkippedForProd(t *testing.T) {
	var stderr bytes.Buffer
	c := localOnlyTestCmd()
	c.SetErr(&stderr)
	modes := map[string]localonly.Mode{}
	suggestLocalOnly(c, appSecretsTemplate, localonly.ClassProd, modes, func(string) bool { t.Fatal("must not prompt"); return true })
	assert.Empty(t, modes)
	assert.Empty(t, stderr.String())
}

func TestFormatLocalOnly(t *testing.T) {
	assert.Equal(t, "-", formatLocalOnly(nil))
	assert.Equal(t, "A=ephemeral,B=operation", formatLocalOnly(map[string]localonly.Mode{"B": localonly.Operation, "A": localonly.Ephemeral}))
}
