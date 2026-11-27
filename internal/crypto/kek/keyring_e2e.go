//go:build keylatch_e2e

package kek

import "os"

// The end-to-end suite runs on CI machines whose OS keyring may block on an
// unlock prompt. This file is compiled only into the binary that suite builds
// with -tags keylatch_e2e; a release binary has no such variable.
func init() {
	if os.Getenv("KEYLATCH_E2E_NO_OS_KEYRING") != "" {
		osKeyringDisabled = func() bool { return true }
	}
}
