package contained

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close() //nolint:errcheck
	return l.Addr().(*net.TCPAddr).Port
}

func realTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return d
}

func TestSeatbeltRunsACommandAndKeepsTheHomeOut(t *testing.T) {
	if !Probe().Supported {
		t.Skip("sandbox-exec is not available")
	}
	project, root, egress := realTemp(t), realTemp(t), realTemp(t)
	secret := filepath.Join(realTemp(t), "outside")
	require.NoError(t, os.WriteFile(secret, []byte("hidden"), 0o600))
	spec := Spec{
		Argv: []string{"/bin/sh", "-c", "echo ran:$HOME; cat '" + secret + "' || echo denied"},
		Env:  []string{"PATH=/usr/bin:/bin"}, Project: project, EgressDir: egress, RootDir: root, ProxyPort: freePort(t),
	}
	c, err := (&Native{}).Start(spec)
	require.NoError(t, err)
	out, _ := io.ReadAll(c.Stdout())
	code, err := c.Wait()
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	assert.Contains(t, string(out), "ran:"+filepath.Join(root, "home"))
	assert.Contains(t, string(out), "denied")
	assert.NotContains(t, string(out), "hidden")
	_, statErr := os.Stat(filepath.Join(root, "home"))
	assert.True(t, os.IsNotExist(statErr), "the private home is removed with the run")
}

func TestSeatbeltRefusesATerminalRun(t *testing.T) {
	_, err := (&Native{}).Start(Spec{Argv: []string{"x"}, Project: "/p", EgressDir: "/e", RootDir: "/r", TTY: &Winsize{}})
	assert.ErrorContains(t, err, "terminal")
}
