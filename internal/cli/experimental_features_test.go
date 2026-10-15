//go:build experimental

package cli_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keylatch/keylatch/internal/cli"
)

func TestExperimentalBuildRegistersTeamAndTrust(t *testing.T) {
	root := cli.NewRootCommand()
	for _, name := range []string{"team", "trust", "shared-secret"} {
		assert.NotNil(t, subcommand(root, name), "%q must be registered in experimental builds", name)
	}
	backend := subcommand(root, "backend")
	if assert.NotNil(t, backend) {
		assert.NotNil(t, subcommand(backend, "vault"))
	}
}
