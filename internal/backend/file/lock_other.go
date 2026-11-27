//go:build !unix && !windows

package file

import "os"

// No cross-process lock is available on this platform; writes are serialized
// within the process only.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
