package paths_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/paths"
)

func TestDefaultConfigIgnoresOverrides(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	want := filepath.Join(home, ".keylatch", "config.json")
	if runtime.GOOS == "linux" {
		want = filepath.Join(home, ".config", "keylatch", "config.json")
	}
	if got := paths.DefaultConfig(home); got != want {
		t.Fatalf("DefaultConfig = %q, want %q", got, want)
	}
}

func TestDaemonPaths(t *testing.T) {
	dir := t.TempDir()
	env := fixedLookup(map[string]string{"KEYLATCH_CONFIG_DIR": dir})

	if got, want := paths.KeyOperations(env), filepath.Join(dir, "key-operations.json"); got != want {
		t.Errorf("KeyOperations = %q, want %q", got, want)
	}
	if got, want := paths.SessionTicketKey(env), filepath.Join(paths.KeyringDir(env), "session-ticket.key"); got != want {
		t.Errorf("SessionTicketKey = %q, want %q", got, want)
	}
}

func TestControlSocket(t *testing.T) {
	if got := paths.ControlSocket(fixedLookup(map[string]string{"KEYLATCH_SOCKET": "/s/k.sock", "XDG_RUNTIME_DIR": "/run/u"})); got != "/s/k.sock" {
		t.Errorf("override: got %q", got)
	}
	if got, want := paths.ControlSocket(fixedLookup(map[string]string{"XDG_RUNTIME_DIR": "/run/u"})), filepath.Join("/run/u", "keylatch", "keylatchd.sock"); got != want {
		t.Errorf("XDG: got %q, want %q", got, want)
	}
	want := filepath.Join(os.TempDir(), fmt.Sprintf("keylatch-%d", os.Getuid()), "keylatchd.sock")
	if got := paths.ControlSocket(fixedLookup(nil)); got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}
}

func TestSSHAgentSocket(t *testing.T) {
	if got := paths.SSHAgentSocket(fixedLookup(map[string]string{"KEYLATCH_SSH_AGENT_SOCKET": "/a/agent.sock"})); got != "/a/agent.sock" {
		t.Errorf("override: got %q", got)
	}
	if got, want := paths.SSHAgentSocket(fixedLookup(map[string]string{"XDG_RUNTIME_DIR": "/run/u"})), filepath.Join("/run/u", "keylatch", "ssh-agent.sock"); got != want {
		t.Errorf("default: got %q, want %q", got, want)
	}
}
