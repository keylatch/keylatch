//go:build !experimental

package cli

import "github.com/spf13/cobra"

// registerExperimentalFeatures registers nothing in release builds.
func registerExperimentalFeatures(*cobra.Command) {}
