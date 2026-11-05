//go:build !experimental

package cli

import "github.com/spf13/cobra"

// registerBackendVault registers nothing: the Vault Transit root-of-trust
// commands are only built with the experimental tag.
func registerBackendVault(*cobra.Command) {}
