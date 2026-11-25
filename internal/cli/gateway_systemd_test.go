package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUserManager replaces the systemctl and loginctl seams and records calls.
type fakeUserManager struct {
	calls   [][]string
	outputs map[string]string
}

func installFakeUserManager(t *testing.T) *fakeUserManager {
	t.Helper()
	f := &fakeUserManager{outputs: map[string]string{}}
	origSystemctl, origLoginctl := systemctlRunFunc, loginctlRunFunc
	t.Cleanup(func() { systemctlRunFunc, loginctlRunFunc = origSystemctl, origLoginctl })
	systemctlRunFunc = func(args ...string) ([]byte, error) {
		f.calls = append(f.calls, append([]string{"systemctl"}, args...))
		return []byte(f.outputs[args[0]]), nil
	}
	loginctlRunFunc = func(args ...string) ([]byte, error) {
		f.calls = append(f.calls, append([]string{"loginctl"}, args...))
		return []byte(f.outputs["loginctl"]), nil
	}
	return f
}

func systemdTestEnv(t *testing.T) (home, binary string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("KEYLATCH_CONFIG_DIR", "")
	t.Setenv("KEYLATCH_GATEWAY_DIR", filepath.Join(home, "gw"))
	binary = filepath.Join(home, "keylatch")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755)) //nolint:gosec // test fixture
	binary, err := filepath.EvalSymlinks(binary)
	require.NoError(t, err)
	return home, binary
}

func runSystemd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newGatewaySystemdCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestGatewaySystemdPrint_BindsConfiguredAddressViaCredential(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)

	out, err := runSystemd(t, "print", "--listen", "10.0.2.2:8788", "--allow-source", "10.0.2.0/24", "--binary", binary)
	require.NoError(t, err)

	assert.Contains(t, out, "ExecStart="+binary+" gateway up --allow-source 10.0.2.0/24\n")
	assert.Contains(t, out, "LoadCredentialEncrypted=kek:")
	assert.Contains(t, out, "Environment=KEYLATCH_AGE_IDENTITY=%d/kek")
	assert.Contains(t, out, "EnvironmentFile=")
	assert.NotContains(t, out, "0.0.0.0")
	assert.NotContains(t, out, "insecure")
}

func TestValidateGatewayListen(t *testing.T) {
	for _, ok := range []string{"192.168.122.1:7878", "127.0.0.1:7878", "[fd00::1]:7878"} {
		assert.NoError(t, validateGatewayListen(ok), ok)
	}
	for _, bad := range []string{"0.0.0.0:7878", "[::]:7878", ":7878", "localhost:7878", "bridge.local:7878", "192.168.122.1", "192.168.122.1:0"} {
		assert.Error(t, validateGatewayListen(bad), bad)
	}
}

func TestGatewaySystemdInstall_WritesUnitAndEnvFileWithoutStarting(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)

	out, err := runSystemd(t, "install", "--listen", "192.168.122.1:7878", "--allow-source", "192.168.122.0/24", "--binary", binary)
	require.NoError(t, err)

	unitPath := filepath.Join(home, "xdg", "systemd", "user", systemdUnitName)
	unit, err := os.ReadFile(unitPath)
	require.NoError(t, err)
	assert.Contains(t, string(unit), "ExecStart="+binary+" gateway up --allow-source 192.168.122.0/24\n")

	envPath := filepath.Join(home, "gw", "systemd.env")
	envFile, err := os.ReadFile(envPath)
	require.NoError(t, err)
	assert.Contains(t, string(envFile), "KEYLATCH_GATEWAY_LISTEN=192.168.122.1:7878\n")
	info, err := os.Stat(envPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	assert.Equal(t, [][]string{{"systemctl", "daemon-reload"}}, fake.calls)
	assert.Contains(t, out, "vault key credential missing")
	assert.Contains(t, out, "not started")
}

func TestGatewaySystemdInstall_NowEnablesUnit(t *testing.T) {
	_, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)

	_, err := runSystemd(t, "install", "--listen", "192.168.122.1:7878", "--allow-source", "192.168.122.0/24", "--binary", binary, "--now")
	require.NoError(t, err)

	assert.Contains(t, fake.calls, []string{"systemctl", "enable", "--now", systemdUnitName})
}

func TestGatewaySystemdInstall_RefusesWildcardListen(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)

	_, err := runSystemd(t, "install", "--listen", "0.0.0.0:7878", "--allow-any-source", "--binary", binary)
	require.Error(t, err)

	assert.Empty(t, fake.calls)
	_, statErr := os.Stat(filepath.Join(home, "xdg", "systemd", "user", systemdUnitName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestGatewaySystemdInstall_RefusesUnsafeBinaryPath(t *testing.T) {
	home, _ := systemdTestEnv(t)
	installFakeUserManager(t)
	spaced := filepath.Join(home, "with space")
	require.NoError(t, os.WriteFile(spaced, []byte("x"), 0o755)) //nolint:gosec // test fixture

	_, err := runSystemd(t, "install", "--listen", "192.168.122.1:7878", "--allow-source", "192.168.122.0/24", "--binary", spaced)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

func TestGatewaySystemdUninstall_RemovesUnitKeepsKeyMaterial(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)
	_, err := runSystemd(t, "install", "--listen", "192.168.122.1:7878", "--allow-source", "192.168.122.0/24", "--binary", binary)
	require.NoError(t, err)
	cred := filepath.Join(home, "gw", "kek.cred")
	require.NoError(t, os.WriteFile(cred, []byte("sealed"), 0o600))
	fake.calls = nil

	out, err := runSystemd(t, "uninstall")
	require.NoError(t, err)

	_, statErr := os.Stat(filepath.Join(home, "xdg", "systemd", "user", systemdUnitName))
	assert.True(t, os.IsNotExist(statErr))
	assert.FileExists(t, cred)
	assert.Equal(t, [][]string{{"systemctl", "disable", "--now", systemdUnitName}, {"systemctl", "daemon-reload"}}, fake.calls)
	assert.Contains(t, out, "removed")

	fake.calls = nil
	out, err = runSystemd(t, "uninstall")
	require.NoError(t, err)
	assert.Contains(t, out, "not installed")
	assert.Empty(t, fake.calls)
}

func TestGatewaySystemdStatus_ReportsStateAndLinger(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)
	_, err := runSystemd(t, "install", "--listen", "192.168.122.1:7878", "--allow-source", "192.168.122.0/24", "--binary", binary)
	require.NoError(t, err)
	fake.outputs["is-enabled"] = "enabled\n"
	fake.outputs["is-active"] = "active\n"
	fake.outputs["loginctl"] = "yes\n"
	require.NoError(t, os.WriteFile(filepath.Join(home, "gw", "kek.cred"), []byte("sealed"), 0o600))

	out, err := runSystemd(t, "status")
	require.NoError(t, err)

	for _, want := range []string{"enabled      enabled", "active       active", "linger       yes", "credential   present", "unit         present"} {
		assert.Contains(t, out, want)
	}
	assert.False(t, strings.Contains(out, "missing"))
}

func execStartOf(t *testing.T, unit string) string {
	t.Helper()
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
			return v
		}
	}
	t.Fatal("no ExecStart")
	return ""
}

func TestGatewaySystemdPrint_AllowSourceForms(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)

	out, err := runSystemd(t, "print", "--listen", "10.0.2.2:8788", "--binary", binary,
		"--allow-source", "10.0.2.7/24", "--allow-source", "fd00:1::/64", "--github-mint", "github-app")
	require.NoError(t, err)
	assert.Equal(t, binary+" gateway up --allow-source 10.0.2.0/24 --allow-source fd00:1::/64 --github-mint github-app", execStartOf(t, out))
}

func TestGatewaySystemdInstall_NonLoopbackNeedsAllowSource(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)

	for _, listen := range []string{"10.0.2.2:8788", "[fd00::1]:8788"} {
		_, err := runSystemd(t, "install", "--listen", listen, "--binary", binary)
		require.Error(t, err, listen)
		assert.Contains(t, err.Error(), "--allow-source")
		assert.Contains(t, err.Error(), "--allow-any-source")
	}
	assert.Empty(t, fake.calls)
	_, statErr := os.Stat(filepath.Join(home, "xdg", "systemd", "user", systemdUnitName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestGatewaySystemdInstall_AllowAnySourceIsExplicit(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)

	out, err := runSystemd(t, "print", "--listen", "10.0.2.2:8788", "--binary", binary, "--allow-any-source")
	require.NoError(t, err)
	assert.Equal(t, binary+" gateway up", execStartOf(t, out))

	_, err = runSystemd(t, "print", "--listen", "10.0.2.2:8788", "--binary", binary, "--allow-any-source", "--allow-source", "10.0.2.0/24")
	require.Error(t, err)
}

func TestGatewaySystemdInstall_LoopbackNeedsNoAllowSource(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)

	out, err := runSystemd(t, "print", "--listen", "127.0.0.1:8788", "--binary", binary)
	require.NoError(t, err)
	assert.Equal(t, binary+" gateway up", execStartOf(t, out))
}

func TestGatewaySystemdInstall_RejectsBadAllowSourceAndConnection(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)

	for _, extra := range [][]string{
		{"--allow-source", "10.0.2.0"},
		{"--allow-source", "not-a-cidr"},
		{"--allow-source", "10.0.2.0/24", "--github-mint", "x --unsafe-bind-all"},
		{"--allow-source", "10.0.2.0/24", "--github-mint", "a\nExecStartPost=/bin/sh"},
	} {
		args := append([]string{"print", "--listen", "10.0.2.2:8788", "--binary", binary}, extra...)
		_, err := runSystemd(t, args...)
		require.Error(t, err, extra)
	}
}
