//go:build windows

// Package token — Windows best-effort consumption log implementation.
// FIND3-009: On Windows, flock is not available; we use O_CREATE|O_EXCL retry loop.
package token

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// consumeTokenUseLog implements best-effort FIND3-009 on Windows.
func consumeTokenUseLog(t *Token) bool {
	logPath := t.ConsumptionLogPath
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
	count, err := countTokenLogLines(logPath)
	if err != nil && !os.IsNotExist(err) {
		return false
	}
	if count >= t.MaxUses {
		return false
	}

	// Append one JSON record.
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()

	rec := consumeTokenLogEntry{
		TokenID: t.ID,
		UsedAt:  time.Now().UTC().Format(time.RFC3339Nano),
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
