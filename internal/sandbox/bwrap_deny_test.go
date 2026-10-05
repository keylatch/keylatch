//go:build linux

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBwrapDenyMasksAfterBinds(t *testing.T) {
	work := t.TempDir()
	secretDir := filepath.Join(work, "secrets")
	secretFile := filepath.Join(work, "token.txt")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := &SandboxManifest{
		Executable: "/usr/bin/true",
		BindMounts: []BindMount{{Src: work, Dest: "/work"}},
		Deny:       []string{"/work/secrets", "/work/token.txt", "/work/missing", "/tmp/scratch", "/etc/shadow"},
	}
	args, err := buildBwrapArgs(m, nil)
	if err != nil {
		t.Fatal(err)
	}

	bind := indexPair(args, "--bind", work)
	dirMask := indexPair(args, "--tmpfs", "/work/secrets")
	fileMask := indexTriple(args, "--ro-bind", "/dev/null", "/work/token.txt")
	if bind < 0 || dirMask < 0 || fileMask < 0 {
		t.Fatalf("missing bind or masks in %v", args)
	}
	if dirMask < bind || fileMask < bind {
		t.Fatalf("masks must follow the bind they cover: %v", args)
	}
	if slices.Contains(args, "/work/missing") || slices.Contains(args, "/tmp/scratch") {
		t.Fatalf("paths with nothing to mask must not produce mounts: %v", args)
	}
	if _, err := os.Lstat("/etc/shadow"); err == nil && indexTriple(args, "--ro-bind", "/dev/null", "/etc/shadow") < 0 {
		t.Fatalf("deny path under a system bind not masked: %v", args)
	}
}

func TestBwrapDenyUsesLastCoveringMount(t *testing.T) {
	outer := t.TempDir()
	inner := t.TempDir()
	if err := os.Mkdir(filepath.Join(inner, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := &SandboxManifest{
		Executable: "/usr/bin/true",
		BindMounts: []BindMount{{Src: outer, Dest: "/work"}, {Src: inner, Dest: "/work/sub"}},
		Deny:       []string{"/work/sub/keys"},
	}
	args, err := buildBwrapArgs(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if indexPair(args, "--tmpfs", "/work/sub/keys") < 0 {
		t.Fatalf("deny path backed by the inner mount not masked: %v", args)
	}
}

func TestBwrapDenyRefusesUnenforceable(t *testing.T) {
	work := t.TempDir()
	if err := os.Symlink("/etc/hostname", filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	for _, deny := range []string{"/work/link", "relative/path"} {
		m := &SandboxManifest{
			Executable: "/usr/bin/true",
			BindMounts: []BindMount{{Src: work, Dest: "/work"}},
			Deny:       []string{deny},
		}
		if _, err := buildBwrapArgs(m, nil); !errors.Is(err, ErrDenyUnenforceable) {
			t.Errorf("deny %q: got %v, want ErrDenyUnenforceable", deny, err)
		}
	}
}

func indexPair(args []string, flag, value string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return i
		}
	}
	return -1
}

func indexTriple(args []string, flag, a, b string) int {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == a && args[i+2] == b {
			return i
		}
	}
	return -1
}
