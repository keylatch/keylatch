package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// userHost is a Windows host whose process is not elevated.
type userHost struct{}

func (userHost) Elevated() bool                     { return false }
func (userHost) Binary(string) (string, error)      { return "", errors.New("none") }
func (userHost) SecureDir(string, string) error     { return nil }
func (userHost) ServiceExists(string) (bool, error) { return false, nil }
func (userHost) CreateService(brokerd.ServiceSpec) error {
	return nil
}
func (userHost) StartService(string) error         { return nil }
func (userHost) RootStore(string) keys.RootStore   { return keys.SealedFile{} }
func (userHost) ResolveSID(string) (string, error) { return "", errors.New("none") }

func withUserHost(t *testing.T) {
	t.Helper()
	prev := windowsHost
	windowsHost = func() brokerd.WinHost { return userHost{} }
	t.Cleanup(func() { windowsHost = prev })
}

func TestInstallWindowsNeedsAnAdministrator(t *testing.T) {
	withUserHost(t)
	if _, err := installWindows(context.Background(), &bytes.Buffer{}); !errors.Is(err, brokerd.ErrNotAdmin) {
		t.Fatalf("not elevated = %v", err)
	}
}

func TestEnrollWindowsNeedsAKeyAndAnAdministrator(t *testing.T) {
	withUserHost(t)
	if _, err := enrollWindows(context.Background(), `PC\alice`, ""); err == nil || !strings.Contains(err.Error(), "--key-file") {
		t.Fatalf("no key file = %v", err)
	}
	if _, err := enrollWindows(context.Background(), `PC\alice`, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing key file enrolled")
	}
	key := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(key, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollWindows(context.Background(), `PC\alice`, key); !errors.Is(err, brokerd.ErrNotAdmin) {
		t.Fatalf("not elevated = %v", err)
	}
}

func TestEnrollPresenceCommandRefusals(t *testing.T) {
	cmd := newBrokerEnrollPresenceCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--user") {
		t.Fatalf("no --user = %v", err)
	}
	if runtime.GOOS == "linux" {
		cmd = newBrokerEnrollPresenceCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--user", "alice"})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "polkit") {
			t.Fatalf("Linux = %v", err)
		}
	}
}

func TestMacEnrollmentRefusals(t *testing.T) {
	if _, err := enrollMac(context.Background(), "no-such-user-keylatch", ""); err == nil {
		t.Fatal("an unknown user enrolled")
	}
	if err := ownByBroker(filepath.Join(t.TempDir(), "x")); err == nil {
		t.Skip("this host has a broker account")
	}
	prev := brokerEuid
	brokerEuid = func() int { return 1000 }
	defer func() { brokerEuid = prev }()
	if runtime.GOOS == "windows" {
		t.Skip("Windows user ids are SIDs; the macOS enrollment path does not run there")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	self := u.Username
	key := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(key, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollMac(context.Background(), self, key); !errors.Is(err, brokerd.ErrNotRoot) {
		t.Fatalf("not root = %v", err)
	}
}
