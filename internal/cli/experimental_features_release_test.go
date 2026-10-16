//go:build !experimental

package cli_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keylatch/keylatch/internal/cli"
)

func TestReleaseBuildRegistersNoExperimentalFeatures(t *testing.T) {
	root := cli.NewRootCommand()
	for _, name := range []string{"team", "trust", "shared-secret"} {
		assert.Nil(t, subcommand(root, name), "%q must not exist without the experimental tag", name)
	}
	for _, g := range root.Groups() {
		assert.NotEqual(t, "team", g.ID, "the team group is registered only in experimental builds")
	}
	backend := subcommand(root, "backend")
	if assert.NotNil(t, backend) {
		assert.Nil(t, subcommand(backend, "vault"))
		assert.NotNil(t, subcommand(backend, "list"))
	}
}
