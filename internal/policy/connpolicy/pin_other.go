//go:build !unix

package connpolicy

import (
	"errors"
	"io/fs"
)

// rootOwnedAndClosed always fails: pinning needs file ownership that this
// platform does not report, so a pinned command is never trusted here.
func rootOwnedAndClosed(string, fs.FileInfo) error {
	return errors.New("pinned executables are not supported on this platform")
}
