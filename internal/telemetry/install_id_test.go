package telemetry_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/telemetry"
)

func TestInstallID_IsStable(t *testing.T) {
	dir := t.TempDir()

	id1, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32-char hex ID, got %d chars: %q", len(id1), id1)
	}

	// Second call must return the same ID.
	id2, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if id1 != id2 {
		t.Errorf("install ID changed between calls: %q vs %q", id1, id2)
	}

	// Third call with fresh state from disk must still match.
	id3, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if id1 != id3 {
		t.Errorf("install ID not stable across reads: %q vs %q", id1, id3)
	}
}

func TestInstallID_FilePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission test not applicable on Windows")
	}

	dir := t.TempDir()
	_, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("EnsureInstallID: %v", err)
	}

	path := filepath.Join(dir, "install_id")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat install_id: %v", err)
	}

	const wantPerm = 0o600
	got := info.Mode().Perm()
	if got != wantPerm {
		t.Errorf("install_id perms: got %04o, want %04o", got, wantPerm)
	}
}

func TestInstallID_MalformedFileIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "install_id")

	// Write a malformed (too short) install_id.
	if err := os.WriteFile(path, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("EnsureInstallID with malformed file: %v", err)
	}
	if len(id) != 32 {
		t.Errorf("expected 32-char hex ID after regeneration, got %d chars: %q", len(id), id)
	}
}

func TestInstallID_CreatesDataDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "nested", "datadir")

	id, err := telemetry.EnsureInstallID(dir)
	if err != nil {
		t.Fatalf("EnsureInstallID with missing dataDir: %v", err)
	}
	if len(id) != 32 {
		t.Errorf("expected 32-char hex ID, got %d chars", len(id))
	}

	// Verify the file was created.
	if _, err := os.Stat(filepath.Join(dir, "install_id")); err != nil {
		t.Errorf("install_id file not created: %v", err)
	}
}
