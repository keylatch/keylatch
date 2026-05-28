// Package gateway — PID file management for the background gateway process.
package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WritePID writes pid to path atomically with mode 0o600.
// The file contains the PID as a decimal string followed by a newline.
// Atomicity is achieved by writing to a .tmp file and renaming into place.
func WritePID(path string, pid int) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return fmt.Errorf("gateway: write PID tmp %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("gateway: rename PID file: %w", err)
	}
	return nil
}

// ReadPID reads and parses the PID from path.
// Returns (0, nil) if the file does not exist.
// Returns an error if the file exists but cannot be read or parsed.
func ReadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("gateway: read PID file %q: %w", path, err)
	}
	s := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("gateway: parse PID %q: %w", s, err)
	}
	return pid, nil
}

// RemovePID removes the PID file at path, ignoring not-found errors.
func RemovePID(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("gateway: remove PID file %q: %w", path, err)
	}
	return nil
}

// IsRunning returns true if the process identified by pidPath exists and is alive.
// The liveness probe is platform-specific: signal(0) on Unix, OpenProcess on Windows.
// Note: this is a best-effort check and does not guarantee exclusivity due to PID-reuse races.
func IsRunning(pidPath string) (pid int, running bool) {
	pid, err := ReadPID(pidPath)
	if err != nil || pid == 0 {
		return 0, false
	}
	return pid, isAlive(pid)
}

// SendTerm sends a termination signal to the process identified by pidPath and removes the PID file.
// Returns nil if the process was not found (already stopped).
func SendTerm(pidPath string) error {
	pid, err := ReadPID(pidPath)
	if err != nil {
		return err
	}
	if pid == 0 {
		return nil // not running
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = RemovePID(pidPath)
		return nil
	}
	if err := terminateProcess(proc); err != nil {
		_ = RemovePID(pidPath)
		return fmt.Errorf("gateway: terminate %d: %w", pid, err)
	}
	return RemovePID(pidPath)
}
