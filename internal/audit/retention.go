package audit

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/config"
)

// DefaultRetentionDays is the fallback when no retention is configured.
const DefaultRetentionDays = 30

// DefaultSweepIntervalHours is the fallback sweep interval.
const DefaultSweepIntervalHours = 24

// LoadRetentionDays returns the configured audit retention days from cfg.
// Falls back to DefaultRetentionDays when the field is zero or out of range.
func LoadRetentionDays(cfg config.AuditConfig) int {
	d := cfg.RetentionDays
	if d < 1 || d > 3650 {
		return DefaultRetentionDays
	}
	return d
}

// LoadSweepIntervalHours returns the configured sweep interval from cfg.
// Falls back to DefaultSweepIntervalHours when the field is zero or out of range.
func LoadSweepIntervalHours(cfg config.AuditConfig) int {
	h := cfg.SweepIntervalHours
	if h < 1 {
		return DefaultSweepIntervalHours
	}
	return h
}

// RunAuditRetentionSweep removes audit log entries (rotated files) older than
// retentionDays. It operates on .1 rotation files in the same directory as logPath.
// Errors are logged at WARN level but do not terminate the goroutine.
func RunAuditRetentionSweep(logPath string, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	dir := filepath.Dir(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("audit retention sweep: readdir %q: %w", dir, err)
	}

	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		// Only consider rotated log files (audit.log.1, audit.log.2, etc.)
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) && name != filepath.Base(logPath) {
			if rmErr := os.Remove(fullPath); rmErr != nil && firstErr == nil {
				firstErr = rmErr
			}
		}
	}
	return firstErr
}

// StartRetentionSweepLoop starts a background goroutine that calls
// RunAuditRetentionSweep on a configurable interval. The goroutine
// stops when ctx is cancelled (graceful shutdown).
// Sweep errors are logged at WARN level; the goroutine continues.
func StartRetentionSweepLoop(ctx context.Context, logPath string, retentionDays, intervalHours int) {
	interval := time.Duration(intervalHours) * time.Hour
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := RunAuditRetentionSweep(logPath, retentionDays); err != nil {
					log.Printf("WARN: audit retention sweep: %v", err)
				}
			}
		}
	}()
}
