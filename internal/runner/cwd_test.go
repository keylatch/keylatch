package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWorkingDirIgnoresPWD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PWD is not consulted on Windows")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(real)
	t.Setenv("PWD", link)

	got, err := workingDir()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("workingDir = %q, want %q (PWD was %q)", got, want, link)
	}
}
