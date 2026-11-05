//go:build windows

package doctor

import "os"

// os.FindProcess opens the process on Windows and fails when it does not exist.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = proc.Release()
	return true
}
