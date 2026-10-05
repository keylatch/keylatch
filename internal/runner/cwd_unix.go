//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package runner

import "golang.org/x/sys/unix"

// workingDir returns the kernel's view of the working directory. os.Getwd
// returns $PWD whenever it names the same directory, and the caller sets
// $PWD, so a symlinked path could stand in for the real one.
func workingDir() (string, error) {
	return unix.Getwd()
}
