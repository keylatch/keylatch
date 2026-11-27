//go:build windows

package token

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// consumeTokenUseLog records one use under an exclusive lock and reports
// whether the token had a use left. Any failure counts as no use left.
func consumeTokenUseLog(t *Token) bool {
	logPath := t.ConsumptionLogPath
	unlock, err := lockExclusive(logPath + ".lock")
	if err != nil {
		return false
	}
	defer unlock()

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
	defer f.Close() //nolint:errcheck // Sync below reports write failures

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
