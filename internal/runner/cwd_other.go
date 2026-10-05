//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package runner

import "os"

// workingDir returns the working directory.
func workingDir() (string, error) {
	return os.Getwd()
}
