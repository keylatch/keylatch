package contained

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func shell(t *testing.T, script string, hooks hostHooks) Child {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake target is a shell script")
	}
	if hooks.signal == nil {
		hooks.signal = func(p *os.Process, _ int) error { return p.Kill() }
	}
	if hooks.kill == nil {
		hooks.kill = func(p *os.Process) { _ = p.Kill() }
	}
	c, err := startHostCmd(exec.Command("/bin/sh", "-c", script), hooks)
	require.NoError(t, err)
	return c
}

func TestHostChildStreamsAndExitStatus(t *testing.T) {
	cleaned := 0
	c := shell(t, "read l; echo out:$l; echo err >&2; exit 3", hostHooks{cleanup: func() { cleaned++ }})
	_, err := io.WriteString(c.Stdin(), "x\n")
	require.NoError(t, err)
	out, _ := io.ReadAll(c.Stdout())
	errOut, _ := io.ReadAll(c.Stderr())
	code, err := c.Wait()
	require.NoError(t, err)
	assert.Equal(t, 3, code)
	assert.Equal(t, "out:x\n", string(out))
	assert.Equal(t, "err\n", string(errOut))
	assert.Equal(t, 1, cleaned)
	assert.Error(t, c.Resize(1, 1))
}

func TestHostChildKillAndSignal(t *testing.T) {
	c := shell(t, "sleep 30", hostHooks{})
	c.Kill()
	code, err := c.Wait()
	require.NoError(t, err)
	assert.Equal(t, 137, code, "a killed run reports 128 plus the signal")

	c = shell(t, "sleep 30", hostHooks{})
	require.NoError(t, c.Signal(9))
	code, _ = c.Wait()
	assert.Equal(t, 137, code)
}

func TestHostChildStartFailureCleansUp(t *testing.T) {
	cleaned := false
	_, err := startHostCmd(exec.Command(filepath.Join(t.TempDir(), "missing")), hostHooks{cleanup: func() { cleaned = true }})
	assert.Error(t, err)
	assert.True(t, cleaned)
}

func TestHostExitStatusReportsOtherErrors(t *testing.T) {
	code, err := hostExitStatus(io.ErrClosedPipe)
	assert.Equal(t, 0, code)
	assert.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestLookPathIn(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool.exe")
	require.NoError(t, os.WriteFile(tool, nil, 0o755)) //nolint:gosec // G306: a fixture
	env := []string{"A=b", "Path=relative" + string(os.PathListSeparator) + dir}
	got, err := lookPathIn(env, "tool", []string{".exe"})
	require.NoError(t, err)
	assert.Equal(t, tool, got, "the name matches case-insensitively and relative entries are skipped")
	_, err = lookPathIn(env, "tool", nil)
	assert.Error(t, err)
	got, err = lookPathIn(nil, "/bin/sh", nil)
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", got, "a name with a separator is used as given")
}

func TestReplaceEnvAndWriteHoney(t *testing.T) {
	assert.Equal(t, []string{"B=2", "A=9"}, replaceEnv([]string{"A=1", "B=2"}, "A", "9"))
	home := t.TempDir()
	require.NoError(t, writeHoney(home, []HoneyFile{{Path: ".aws/credentials", Content: "decoy"}}))
	b, err := os.ReadFile(filepath.Join(home, ".aws", "credentials"))
	require.NoError(t, err)
	assert.Equal(t, "decoy", string(b))
	assert.Error(t, writeHoney(filepath.Join(home, ".aws", "credentials"), []HoneyFile{{Path: "x", Content: "y"}}))
}
