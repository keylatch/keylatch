package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAllowedCommand(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	dir := t.TempDir()
	planted := filepath.Join(dir, "sh")
	if err := os.WriteFile(planted, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		entries []string
		argv    []string
		want    bool
	}{
		{"bare name", []string{"sh "}, []string{"sh", "-c", "true"}, true},
		{"resolved path of the same executable", []string{"sh "}, []string{sh, "-c", "true"}, true},
		{"prefix is not a match", []string{"sh "}, []string{"shell", "-c", "true"}, false},
		{"suffix is not a match", []string{"sh "}, []string{"ssh"}, false},
		{"python3evil", []string{"python3 "}, []string{"python3evil", "x.py"}, false},
		{"planted copy elsewhere", []string{"sh "}, []string{planted, "-c", "true"}, false},
		{"relative traversal", []string{"sh "}, []string{"../sh"}, false},
		{"argument pattern matches", []string{"sh -c"}, []string{"sh", "-c", "true"}, true},
		{"argument pattern differs", []string{"sh -c"}, []string{"sh", "-s"}, false},
		{"argument pattern missing", []string{"sh -c"}, []string{"sh"}, false},
		{"directory pattern", []string{"sh scripts/"}, []string{"sh", "scripts/run.sh"}, true},
		{"directory pattern escape", []string{"sh scripts/"}, []string{"sh", "scripts/../evil.sh"}, false},
		{"directory pattern elsewhere", []string{"sh scripts/"}, []string{"sh", "other/run.sh"}, false},
		{"wildcard argument", []string{"sh * -x"}, []string{"sh", "anything", "-x"}, true},
		{"absolute name, bare argv0", []string{sh + " "}, []string{"sh"}, false},
		{"empty allowlist", nil, []string{"sh"}, false},
		{"empty command", []string{"sh "}, nil, false},
		{"blank entry", []string{"   "}, []string{"sh"}, false},
	}
	// Allowlist entries are split on whitespace, so an executable whose path
	// contains a space (C:\Program Files\...) cannot be named by absolute path.
	if !strings.ContainsAny(sh, " \t") {
		cases = append(cases, struct {
			name    string
			entries []string
			argv    []string
			want    bool
		}{"absolute name must be argv0", []string{sh + " "}, []string{sh, "-c", "true"}, true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ResolveAllowedCommand(tc.entries, tc.argv)
			if ok != tc.want {
				t.Fatalf("ResolveAllowedCommand(%q, %q) = %v, want %v", tc.entries, tc.argv, ok, tc.want)
			}
			if ok && !filepath.IsAbs(got[0]) {
				t.Errorf("resolved argv[0] %q is not absolute", got[0])
			}
		})
	}
}
