package grant

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBareProgramIgnoresCallerPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bare program names are not resolved on Windows")
	}
	trusted, evil := t.TempDir(), t.TempDir()
	for _, dir := range []string{trusted, evil} {
		if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := commandSearchPath
	commandSearchPath = []string{trusted}
	t.Cleanup(func() { commandSearchPath = prev })
	t.Setenv("PATH", evil+string(os.PathListSeparator)+os.Getenv("PATH"))

	pattern, err := parseCommandPattern("tool deploy")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(trusted, "tool"))
	if pattern[0] != want {
		t.Fatalf("program resolved to %q, want %q", pattern[0], want)
	}
	if !commandMatches(pattern, []string{"tool", "deploy"}) {
		t.Fatal("bare name did not match the program it resolves to")
	}
	if commandMatches(pattern, []string{filepath.Join(evil, "tool"), "deploy"}) {
		t.Fatal("a same-named program elsewhere matched")
	}
}

func TestLegacyCommandStringStillScoped(t *testing.T) {
	prog := filepath.Join(t.TempDir(), "npm")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &Grant{Command: prog + " test"}
	if !commandMatches(g.commandPattern(), []string{prog, "test"}) {
		t.Fatal("legacy command grant does not match its own command")
	}
	if commandMatches(g.commandPattern(), []string{prog, "test", "--script-shell=/tmp/x.sh"}) {
		t.Fatal("legacy command grant matched extra arguments")
	}
	if (&Grant{Command: prog + " test*"}).commandPattern() != nil {
		t.Fatal("legacy glued wildcard still produces a pattern")
	}
}
