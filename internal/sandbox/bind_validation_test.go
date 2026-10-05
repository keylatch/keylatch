package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsUnder(t *testing.T) {
	root := filepath.FromSlash("/home/u/.keylatch")
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/.keylatch", true},
		{"/home/u/.keylatch/vault", true},
		{"/home/u/.keylatch/..foo", true},
		{"/home/u/.keylatch/vault/../keyring", true},
		{"/home/u/.keylatch..x", false},
		{"/home/u/.keylatchx", false},
		{"/home/u", false},
		{"/home/u/.keylatch/..", false},
	}
	for _, tc := range cases {
		if got := isUnder(filepath.FromSlash(tc.path), root); got != tc.want {
			t.Errorf("isUnder(%q, %q) = %v, want %v", tc.path, root, got, tc.want)
		}
	}
}

func TestValidateBindMountsRejectsKeylatchExposure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox mounts are Unix paths")
	}
	base := t.TempDir()
	home := filepath.Join(base, "home")
	state := filepath.Join(home, ".config", "keylatch")
	work := filepath.Join(base, "work")
	for _, d := range []string{state, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	homeLink := filepath.Join(base, "homelink")
	if err := os.Symlink(home, homeLink); err != nil {
		t.Fatal(err)
	}
	protected := []string{filepath.Join(home, ".keylatch"), state}

	cases := []struct {
		name string
		src  string
		dest string
	}{
		{"config dir", state, "/data"},
		{"inside config dir", filepath.Join(state, "vault"), "/data"},
		{"home ancestor", home, "/home"},
		{"filesystem root", "/", "/host"},
		{"dot-config ancestor", filepath.Join(home, ".config"), "/cfg"},
		{"dot-dot traversal", filepath.Join(work, "..", "home", ".config", "keylatch"), "/data"},
		{"symlink to config dir", link, "/data"},
		{"symlink to home", homeLink, "/home"},
		{"under symlink to home", filepath.Join(homeLink, ".config"), "/cfg"},
		{"legacy dir not yet created", filepath.Join(home, ".keylatch", "vault"), "/data"},
		{"dest is config dir", work, state},
		{"dest is root", work, "/"},
		{"relative source", "work", "/work"},
		{"relative dest", work, "work"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &SandboxManifest{BindMounts: []BindMount{{Src: tc.src, Dest: tc.dest, RO: true}}}
			if err := validateBindMounts(m, protected); !errors.Is(err, ErrForbiddenMount) {
				t.Fatalf("mount %q -> %q: got %v, want ErrForbiddenMount", tc.src, tc.dest, err)
			}
		})
	}

	allowed := []BindMount{
		{Src: work, Dest: "/work"},
		{Src: filepath.Join(home, ".keylatch..x"), Dest: "/x"},
		{Src: filepath.Join(home, "project"), Dest: "/project"},
	}
	for _, bm := range allowed {
		m := &SandboxManifest{BindMounts: []BindMount{bm}}
		if err := validateBindMounts(m, protected); err != nil {
			t.Errorf("mount %q -> %q rejected: %v", bm.Src, bm.Dest, err)
		}
	}
}

func TestProtectedPathsCoverConfiguredOverrides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sandbox mounts are Unix paths")
	}
	env := map[string]string{
		"KEYLATCH_CONFIG_DIR": "/srv/kl",
		"KEYLATCH_VAULT_PATH": "/data/vault",
		"XDG_CONFIG_HOME":     "/xdg",
	}
	got := protectedPaths("/home/u", func(k string) string { return env[k] })
	for _, want := range []string{
		filepath.Join("/home/u", ".keylatch"),
		filepath.Join("/home/u", ".config", "keylatch"),
		filepath.Join("/home/u", "Library", "Application Support", "keylatch"),
		filepath.Join("/xdg", "keylatch"),
		"/srv/kl",
		"/data/vault",
	} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("protectedPaths missing %q in %v", want, got)
		}
	}
}
