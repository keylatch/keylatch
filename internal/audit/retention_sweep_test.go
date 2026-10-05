package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionSweepRemovesOnlyOldGenerations(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	old := time.Now().AddDate(0, 0, -40)
	files := map[string]bool{
		"audit.log":      false,
		"audit.log.1":    true,
		"audit.log.12":   true,
		"audit.log.bak":  false,
		"audit-salt":     false,
		"keyring.json":   false,
		"config.json":    false,
		"audit.log.":     false,
		"audit.log.1.gz": false,
	}
	for name := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	fresh := filepath.Join(dir, "audit.log.2")
	if err := os.WriteFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RunAuditRetentionSweep(logPath, 30); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for name, removed := range files {
		_, err := os.Stat(filepath.Join(dir, name))
		if removed != os.IsNotExist(err) {
			t.Errorf("%s: removed=%v, want %v", name, os.IsNotExist(err), removed)
		}
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("recent generation removed: %v", err)
	}
}
