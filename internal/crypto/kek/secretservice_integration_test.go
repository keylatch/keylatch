//go:build linux

package kek

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

func privateSecretBus(t *testing.T) (context.Context, string, []string) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires a private D-Bus and Secret Service")
	}
	busBin, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	home := t.TempDir()
	runtimeDir := filepath.Join(home, "runtime")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	childEnv := []string{"HOME=" + home, "XDG_DATA_HOME=" + filepath.Join(home, "data"), "XDG_RUNTIME_DIR=" + runtimeDir}
	bus := exec.CommandContext(ctx, busBin, "--session", "--nofork", "--print-address=1")
	bus.Env = childEnv
	stdout, err := bus.StdoutPipe()
	require.NoError(t, err)
	startSecretProcess(t, bus)
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "private bus did not publish its address")
	return ctx, scanner.Text(), childEnv
}

func startSecretProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

func TestSecretServiceKEKRoundTrip(t *testing.T) {
	keyringBin, err := exec.LookPath("gnome-keyring-daemon")
	if err != nil {
		t.Skip("gnome-keyring-daemon is unavailable")
	}
	ctx, address, childEnv := privateSecretBus(t)
	keyring := exec.CommandContext(ctx, keyringBin, "--foreground", "--unlock", "--components=secrets")
	keyring.Env = append(childEnv, "DBUS_SESSION_BUS_ADDRESS="+address)
	keyring.Stdin = strings.NewReader("private test keyring password")
	startSecretProcess(t, keyring)
	probe, err := dbus.Connect(address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })
	require.Eventually(t, func() bool {
		var ready bool
		err := probe.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, secretsName).Store(&ready)
		return err == nil && ready
	}, 5*time.Second, 20*time.Millisecond, "private Secret Service did not start")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	store := DefaultIdentityStore()
	require.NotNil(t, store)
	require.Equal(t, "secret-service", store.Name())
	want := identity(0x42)
	require.NoError(t, store.Store("vault-private", want))
	got, err := store.Load("vault-private")
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.NoError(t, store.Store("vault-private", identity(0x43)))
	got, err = store.Load("vault-private")
	require.NoError(t, err)
	require.Equal(t, identity(0x43), got)
	require.NoError(t, store.Delete("vault-private"))
	_, err = store.Load("vault-private")
	require.ErrorIs(t, err, ErrIdentityNotFound)
}

type privatePrompt struct {
	conn    *dbus.Conn
	foreign *dbus.Conn
	body    []any
}

func (p *privatePrompt) Prompt(string) *dbus.Error {
	if p.foreign != nil {
		_ = p.foreign.Emit("/prompt/1", promptIface+".Completed", false, dbus.MakeVariant("forged"))
	}
	if p.body != nil {
		_ = p.conn.Emit("/prompt/1", promptIface+".Completed", p.body...)
	}
	return nil
}

func (*privatePrompt) Dismiss() *dbus.Error { return nil }

func TestSecretServicePromptValidatesReplies(t *testing.T) {
	_, address, _ := privateSecretBus(t)
	for _, tc := range []struct {
		name      string
		body      []any
		foreign   bool
		dismissed bool
		wantErr   string
	}{
		{name: "accepted", body: []any{false, dbus.MakeVariant("")}},
		{name: "dismissed", body: []any{true, dbus.MakeVariant("")}, dismissed: true},
		{name: "missing result", body: []any{false}, wantErr: "malformed"},
		{name: "wrong dismissal type", body: []any{"false", dbus.MakeVariant("")}, wantErr: "malformed"},
		{name: "foreign sender", foreign: true, wantErr: "no answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connect := func() *dbus.Conn {
				conn, err := dbus.Connect(address)
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				return conn
			}
			server := connect()
			owner, err := server.RequestName(secretsName, dbus.NameFlagDoNotQueue)
			require.NoError(t, err)
			require.Equal(t, dbus.RequestNameReplyPrimaryOwner, owner)
			prompt := &privatePrompt{conn: server, body: tc.body}
			if tc.foreign {
				prompt.foreign = connect()
			}
			require.NoError(t, server.Export(prompt, "/prompt/1", promptIface))
			client := &dbusConn{conn: connect()}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			dismissed, err := client.prompt(ctx, "/prompt/1")
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.dismissed, dismissed)
			}
		})
	}
}
