package file_test

import (
	"os"
	"runtime"
	"testing"
)

func assertPrivateFileMode(t *testing.T, path, label string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX file mode bits")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", label, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s mode: got %04o, want 0600", label, info.Mode().Perm())
	}
}
