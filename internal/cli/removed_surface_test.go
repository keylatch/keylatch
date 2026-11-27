package cli_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/cli"
)

func subcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func TestRemovedCommandsAbsent(t *testing.T) {
	root := cli.NewRootCommand()
	for _, name := range []string{"get-masked", "share", "receipts", "rules", "sessions", "projects"} {
		assert.Nil(t, subcommand(root, name), "command %q was removed and must not be registered", name)
	}

	get := subcommand(root, "get")
	require.NotNil(t, get)
	assert.Nil(t, get.Flags().Lookup("masked"), "get --masked was removed")

	if sandbox := subcommand(root, "sandbox"); sandbox != nil {
		assert.Nil(t, subcommand(sandbox, "run"), "sandbox run was removed")
	}

	gateway := subcommand(root, "gateway")
	require.NotNil(t, gateway)
	for _, sub := range gateway.Commands() {
		if sub.Name() != "up" {
			continue
		}
		assert.Nil(t, sub.Flags().Lookup("with-proxy"))
		assert.Nil(t, sub.Flags().Lookup("proxy-port"))
	}
}

func TestNoDuplicateCommands(t *testing.T) {
	root := cli.NewRootCommand()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		seen := map[string]bool{}
		for _, sub := range c.Commands() {
			assert.False(t, seen[sub.Name()], "duplicate command %q under %q", sub.Name(), c.CommandPath())
			seen[sub.Name()] = true
			walk(sub)
		}
	}
	walk(root)
}
