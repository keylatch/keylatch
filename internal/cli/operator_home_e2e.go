//go:build keylatch_e2e

package cli

import "os"

// The end-to-end suite runs the binary with a scratch home, but operator
// settings are read from the account's real home. This file is compiled only
// into the binary that suite builds with -tags keylatch_e2e; a release binary
// has no such variable.
func init() {
	if h := os.Getenv("KEYLATCH_E2E_OPERATOR_HOME"); h != "" {
		operatorHome = func() (string, error) { return h, nil }
	}
}
