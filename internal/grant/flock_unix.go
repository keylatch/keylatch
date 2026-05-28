//go:build !windows

// Package grant — Unix flock-based consumption log implementation.
// FIND3-009: inter-process atomic use counting via append-only log + flock.
package grant

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// consumeUseLog implements FIND3-009 on Unix using flock.
// It flocks the <id>.lock file, counts lines in the consumption log, and
// appends a record if count < MaxUses.
// Returns true if a use was successfully recorded, false if uses are exhausted.
func consumeUseLog(g *Grant) bool {
	logPath := g.ConsumptionLogPath
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return false
	}

	lockPath := logPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer lockFile.Close() //nolint:errcheck // defer close of lock file, error non-actionable

	// Exclusive lock.
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return false
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck

	// Count existing uses.
	count, err := countLines(logPath)
	if err != nil && !os.IsNotExist(err) {
		return false
	}
	if count >= g.MaxUses {
		return false
	}

	// Append one JSON record.
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // defer close of log file, error non-actionable

	rec := map[string]interface{}{
		"grant_id": g.ID,
		"used_at":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		return false
	}
	if err := f.Sync(); err != nil {
		return false
	}
	return true
}

// countLines counts non-empty lines in a file.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // defer close in read-only path, error non-actionable
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if sc.Text() != "" {
			n++
		}
	}
	return n, sc.Err()
}
