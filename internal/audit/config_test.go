package audit_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
)

// TestRetentionConfig_Default verifies that zero/absent RetentionDays falls
// back to the default of 30.
func TestRetentionConfig_Default(t *testing.T) {
	cfg := config.AuditConfig{} // zero value — RetentionDays == 0
	got := audit.LoadRetentionDays(cfg)
	if got != audit.DefaultRetentionDays {
		t.Errorf("LoadRetentionDays(zero) = %d, want %d", got, audit.DefaultRetentionDays)
	}
}

// TestRetentionConfig_FromYAML verifies that a configured value is honoured.
func TestRetentionConfig_FromYAML(t *testing.T) {
	cfg := config.AuditConfig{RetentionDays: 7}
	got := audit.LoadRetentionDays(cfg)
	if got != 7 {
		t.Errorf("LoadRetentionDays(7) = %d, want 7", got)
	}
}

// TestRetentionConfig_MinMaxClamp verifies boundary clamping.
func TestRetentionConfig_MinMaxClamp(t *testing.T) {
	cases := []struct {
		input int
		want  int
	}{
		{0, audit.DefaultRetentionDays},
		{-1, audit.DefaultRetentionDays},
		{3651, audit.DefaultRetentionDays},
		{1, 1},
		{3650, 3650},
	}
	for _, tc := range cases {
		cfg := config.AuditConfig{RetentionDays: tc.input}
		got := audit.LoadRetentionDays(cfg)
		if got != tc.want {
			t.Errorf("LoadRetentionDays(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// TestRetentionConfig_OutOfRange_Errors verifies that config.AuditConfig.Validate
// returns an actionable error for out-of-range RetentionDays values, while in-range
// values are accepted.
func TestRetentionConfig_OutOfRange_Errors(t *testing.T) {
	outOfRange := []int{-1, 3651, 9999}
	for _, v := range outOfRange {
		cfg := config.AuditConfig{RetentionDays: v}
		if err := cfg.Validate(); err == nil {
			t.Errorf("AuditConfig{RetentionDays:%d}.Validate() = nil, want error", v)
		}
	}

	inRange := []int{1, 30, 365, 3650}
	for _, v := range inRange {
		cfg := config.AuditConfig{RetentionDays: v}
		if err := cfg.Validate(); err != nil {
			t.Errorf("AuditConfig{RetentionDays:%d}.Validate() = %v, want nil", v, err)
		}
	}
}

// TestSweep_RemovesOldFiles asserts the sweep removes files older than retention.
func TestSweep_RemovesOldFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Create the main log file.
	if err := os.WriteFile(logPath, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a rotated file that is older than 1-day retention.
	oldFile := filepath.Join(dir, "audit.log.1")
	if err := os.WriteFile(oldFile, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Set mtime to 2 days ago.
	pastTime := time.Now().AddDate(0, 0, -2)
	if err := os.Chtimes(oldFile, pastTime, pastTime); err != nil {
		t.Fatal(err)
	}

	// Create a recent rotated file.
	recentFile := filepath.Join(dir, "audit.log.2")
	if err := os.WriteFile(recentFile, []byte("recent"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sweep with 1-day retention.
	if err := audit.RunAuditRetentionSweep(logPath, 1); err != nil {
		t.Fatalf("RunAuditRetentionSweep: %v", err)
	}

	// Old file should be gone.
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old audit file should have been removed by sweep")
	}

	// Recent file should still exist.
	if _, err := os.Stat(recentFile); err != nil {
		t.Errorf("recent audit file should not have been removed: %v", err)
	}

	// Main log should still exist.
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("main audit log should not have been removed: %v", err)
	}
}

// TestSweep_EmptyDir does not error on an empty directory.
func TestSweep_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := audit.RunAuditRetentionSweep(logPath, 30); err != nil {
		t.Fatalf("unexpected error on empty dir: %v", err)
	}
}
