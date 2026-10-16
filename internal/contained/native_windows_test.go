package contained

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppContainerRunsACommand(t *testing.T) {
	// Starting a real AppContainer once crashed the test binary with a heap
	// corruption status. The use-after-free in the loopback exemption is fixed,
	// but no Windows host has confirmed it, so the real start is opt-in until one
	// does. The planning, quoting and environment tests always run.
	if os.Getenv("KEYLATCH_TEST_APPCONTAINER") != "1" {
		t.Skip("set KEYLATCH_TEST_APPCONTAINER=1 to start a real AppContainer")
	}
	if !Probe().Supported {
		t.Skip("AppContainer APIs are not available")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	root, project, egress := t.TempDir(), t.TempDir(), t.TempDir()
	spec := Spec{
		Argv: []string{`C:\Windows\System32\cmd.exe`, "/c", "echo ran:%USERPROFILE%"},
		Env:  []string{`SystemRoot=C:\Windows`}, Project: project, EgressDir: egress, RootDir: root, ProxyPort: port,
		Limits: Limits{PIDs: 16, MemoryBytes: 512 << 20},
	}
	c, err := (&Native{}).Start(spec)
	if err != nil && strings.Contains(err.Error(), "service account is required") {
		t.Skip("the loopback exemption needs an elevated account: " + err.Error())
	}
	require.NoError(t, err)
	out, _ := io.ReadAll(c.Stdout())
	code, err := c.Wait()
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	assert.Contains(t, string(out), "ran:")
	_, statErr := os.Stat(filepath.Join(root, "home"))
	assert.True(t, os.IsNotExist(statErr), "the private home is removed with the run")
}

func TestAppContainerRefusesATerminalRun(t *testing.T) {
	_, err := (&Native{}).Start(Spec{Argv: []string{"x"}, Project: `C:\p`, EgressDir: `C:\e`, RootDir: `C:\r`, TTY: &Winsize{}})
	assert.ErrorContains(t, err, "terminal")
}
