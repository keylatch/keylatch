package salt_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/audit/salt"
)

func TestSaltLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-salt")

	// Create.
	s1, err := salt.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(s1) != 32 {
		t.Errorf("salt len = %d, want 32", len(s1))
	}

	// Load.
	s2, err := salt.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(s1) != string(s2) {
		t.Error("loaded salt differs from created salt")
	}

	// Wrong mode.
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX file mode bits")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = salt.LoadOrCreate(path)
	if err == nil {
		t.Error("expected error for wrong mode")
	}
}
