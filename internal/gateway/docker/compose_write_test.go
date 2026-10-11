package docker_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/docker"
)

func TestGenerateCompose_Defaults(t *testing.T) {
	data, err := docker.GenerateCompose(docker.ComposeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"ghcr.io/keylatch/keylatch:latest",
		`"127.0.0.1:7878:7878"`,
		`"--port", "7878"`,
		"no-new-privileges:true",
		"read_only: true",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("compose missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "network_mode") || strings.Contains(s, "0.0.0.0") {
		t.Errorf("compose must not use host networking or wildcard bind:\n%s", s)
	}
}

func TestWriteAt_CreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "compose.yml")
	if err := docker.WriteAt(path, docker.ComposeOptions{Port: 9000, Version: "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "keylatch:v1.2.3") || !strings.Contains(string(data), "127.0.0.1:9000:9000") {
		t.Fatalf("unexpected compose:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestWriteAt_Failures(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := docker.WriteAt(filepath.Join(blocker, "sub", "compose.yml"), docker.ComposeOptions{})
	if err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("want mkdir error, got %v", err)
	}
	target := filepath.Join(dir, "isdir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	err = docker.WriteAt(target, docker.ComposeOptions{})
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
}
