//go:build !windows

package salt_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit/salt"
)

func TestLoadOrCreate_CreatesPrivateFileAndReloadsSameBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-salt")
	first, err := salt.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", st.Mode().Perm())
	}
	second, err := salt.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("salt changed between loads")
	}
	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatal("salt is all zeros")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".audit-salt-*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestLoadOrCreate_RejectsGroupOrWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-salt")
	if _, err := salt.LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := salt.LoadOrCreate(path)
		if !errors.Is(err, salt.ErrSaltUnavailable) || !strings.Contains(err.Error(), "want 0600") {
			t.Errorf("mode %04o: got %v", mode, err)
		}
	}
}

func TestLoadOrCreate_DirectoryWithPrivateModeIsUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-salt")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
	_, err := salt.LoadOrCreate(path)
	if !errors.Is(err, salt.ErrSaltUnavailable) || !strings.Contains(err.Error(), "read") {
		t.Fatalf("want read error, got %v", err)
	}
}

func TestLoadOrCreate_StatPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := salt.LoadOrCreate(filepath.Join(dir, "audit-salt"))
	if !errors.Is(err, salt.ErrSaltUnavailable) || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("want stat error, got %v", err)
	}
}

func TestLoadOrCreate_DanglingSymlinkIsReplacedNotFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere", "victim")
	if err := os.Mkdir(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit-salt")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := salt.LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("salt written through symlink to %s: %v", target, err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("salt path mode = %v, want regular 0600 file", st.Mode())
	}
}
