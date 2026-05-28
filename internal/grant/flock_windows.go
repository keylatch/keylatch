//go:build windows

// Package grant — Windows best-effort consumption log implementation.
// FIND3-009: On Windows, flock is not available; we use O_CREATE|O_EXCL retry loop.
package grant

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// consumeUseLog implements best-effort FIND3-009 on Windows.
// It uses an O_CREATE|O_EXCL lock file with a retry loop.
func consumeUseLog(g *Grant) bool {
	logPath := g.ConsumptionLogPath
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return false
	}

	lockPath := logPath + ".lock"

	// Acquire lock via exclusive create (best-effort, up to 50 retries).
	var lockFile *os.File
	var err error
	for i := 0; i < 50; i++ {
		lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return false
	}
	defer func() {
		lockFile.Close()
		os.Remove(lockPath)
	}()

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
	defer f.Close()

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
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if sc.Text() != "" {
			n++
		}
	}
	return n, sc.Err()
}
