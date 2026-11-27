package contained

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if MaybeRun() {
		return
	}
	os.Exit(m.Run())
}

// requireNamespaces skips a test that needs real namespaces, naming the
// capability the host lacks.
func requireNamespaces(t *testing.T) *Native {
	t.Helper()
	r := Probe()
	if missing := r.Missing(); len(missing) > 0 {
		t.Skipf("the sandbox is unavailable here: %s", strings.Join(missing, "; "))
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	return &Native{Binary: exe, Cgroups: true}
}

type world struct {
	spec    Spec
	project string
	egress  string
}

func newWorld(t *testing.T, argv ...string) *world {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "klc")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	w := &world{project: filepath.Join(base, "project"), egress: filepath.Join(base, "egress")}
	for _, d := range []string{w.project, w.egress, filepath.Join(base, "root")} {
		require.NoError(t, os.Mkdir(d, 0o700))
	}
	w.spec = Spec{
		Argv:      argv,
		Env:       []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + DefaultHome, "TMPDIR=/tmp"},
		Project:   w.project,
		EgressDir: w.egress,
		RootDir:   filepath.Join(base, "root"),
		Limits:    Limits{PIDs: 256},
	}
	return w
}

func run(t *testing.T, n *Native, spec Spec, stdin string) (stdout, stderr string, code int) {
	t.Helper()
	c, err := n.Start(spec)
	require.NoError(t, err)
	go func() {
		_, _ = io.WriteString(c.Stdin(), stdin)
		_ = c.Stdin().Close()
	}()
	var out, errOut bytes.Buffer
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(&out, c.Stdout()); done <- struct{}{} }()
	go func() { _, _ = io.Copy(&errOut, c.Stderr()); done <- struct{}{} }()
	waited := make(chan struct{})
	go func() {
		code, err = c.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
		c.Kill()
		t.Fatal("the sandboxed command did not finish")
	}
	<-done
	<-done
	require.NoError(t, err)
	return out.String(), errOut.String(), code
}

func TestRunsACommandInsideTheSandbox(t *testing.T) {
	n := requireNamespaces(t)
	w := newWorld(t, "sh", "-c", `echo "init=$(tr '\0' ' ' </proc/1/cmdline)"; echo "home=$HOME"; echo "uid=$(id -u)"; pwd; echo hi >&2; exit 7`)
	stdout, stderr, code := run(t, n, w.spec, "")
	assert.Equal(t, 7, code)
	assert.Contains(t, stdout, "init="+InitArg0, "the namespace's PID 1 is the Keylatch init")
	assert.Contains(t, stdout, "home="+DefaultHome)
	assert.Contains(t, stdout, "uid=0", "the daemon's user is root inside its own user namespace")
	assert.Contains(t, stdout, w.project, "the working directory is the project")
	assert.Contains(t, stderr, "hi")
}

func TestStdinReachesTheChild(t *testing.T) {
	n := requireNamespaces(t)
	w := newWorld(t, "sh", "-c", `read -r a; read -r b; echo "$b-$a"`)
	stdout, _, code := run(t, n, w.spec, "one\ntwo\n")
	assert.Zero(t, code)
	assert.Equal(t, "two-one\n", stdout)
}

func TestExitStatusesAreReported(t *testing.T) {
	n := requireNamespaces(t)
	for name, tc := range map[string]struct {
		script string
		want   int
	}{
		"zero":             {"exit 0", 0},
		"nonzero":          {"exit 42", 42},
		"killed by signal": {"kill -TERM $$; sleep 5", 128 + 15},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "sh", "-c", tc.script)
			_, _, code := run(t, n, w.spec, "")
			assert.Equal(t, tc.want, code)
		})
	}
	w := newWorld(t, "definitely-not-installed")
	_, stderr, code := run(t, n, w.spec, "")
	assert.Equal(t, exitNotFound, code)
	assert.Contains(t, stderr, "command not found")

	w = newWorld(t, "/")
	_, _, code = run(t, n, w.spec, "")
	assert.Equal(t, exitExecFailed, code)
}

func TestKillEndsTheWholeSandbox(t *testing.T) {
	n := requireNamespaces(t)
	w := newWorld(t, "sh", "-c", `sleep 600 & sleep 600 & wait`)
	c, err := n.Start(w.spec)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	c.Kill()
	done := make(chan int, 1)
	go func() { code, _ := c.Wait(); done <- code }()
	select {
	case code := <-done:
		assert.Equal(t, 128+9, code)
	case <-time.After(30 * time.Second):
		t.Fatal("the sandbox survived Kill")
	}
}

func TestSignalReachesTheCommand(t *testing.T) {
	n := requireNamespaces(t)
	w := newWorld(t, "sh", "-c", `trap 'echo got-term; exit 3' TERM; echo ready; while true; do sleep 0.1; done`)
	c, err := n.Start(w.spec)
	require.NoError(t, err)
	r := c.Stdout()
	buf := make([]byte, 6)
	_, err = io.ReadFull(r, buf)
	require.NoError(t, err)
	require.NoError(t, c.Signal(15))
	rest, _ := io.ReadAll(r)
	code, err := c.Wait()
	require.NoError(t, err)
	assert.Equal(t, 3, code)
	assert.Contains(t, string(rest), "got-term")
	assert.Error(t, c.Resize(10, 10), "a run without a terminal cannot be resized")
}

func TestPTYRunsGetATerminal(t *testing.T) {
	n := requireNamespaces(t)
	w := newWorld(t, "sh", "-c", `[ -t 0 ] && echo "tty0=yes"; stty size; read -r x; echo "typed:$x"`)
	w.spec.TTY = &Winsize{Rows: 31, Cols: 97}
	c, err := n.Start(w.spec)
	require.NoError(t, err)
	assert.Nil(t, c.Stderr())
	require.NoError(t, c.Resize(40, 120))
	_, _ = io.WriteString(c.Stdin(), "hello\n")
	assert.NoError(t, c.Stdin().Close(), "closing stdin of a terminal run is a no-op")
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&out, c.Stdout()); close(done) }()
	code, err := c.Wait()
	require.NoError(t, err)
	<-done
	assert.Zero(t, code)
	assert.Contains(t, out.String(), "tty0=yes")
	assert.Contains(t, out.String(), "typed:hello")
}

func TestStartRefusesWhatItCannotRun(t *testing.T) {
	n := &Native{Binary: "/nonexistent/keylatch"}
	w := newWorld(t, "true")
	_, err := n.Start(w.spec)
	assert.ErrorContains(t, err, "start the sandbox")

	_, err = (&Native{}).Start(w.spec)
	assert.ErrorContains(t, err, "no helper binary")

	bad := w.spec
	bad.Argv = nil
	_, err = n.Start(bad)
	assert.ErrorContains(t, err, "command is required")
	assert.Contains(t, hint(syscall.EPERM), "doctor --sandbox")
	assert.Contains(t, hint(io.EOF), "doctor --sandbox")
}

func TestInitRefusesToRunOutsideANamespace(t *testing.T) {
	var stderr bytes.Buffer
	assert.Equal(t, exitSetupFailed, runInit(initDeps{pid: 5}, &stderr))
	assert.Contains(t, stderr.String(), "only as PID 1")
	stderr.Reset()
	assert.Equal(t, exitSetupFailed, runStage(&fakeRestrictor{}, &stderr))
	assert.Contains(t, stderr.String(), "only under the sandbox init")
}

func TestForwarderReachesTheEgressSocket(t *testing.T) {
	n := requireNamespaces(t)
	// /dev/tcp is a bash feature; dash-based sh cannot open it.
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	w := newWorld(t, bash, "-c", `exec 3<>/dev/tcp/127.0.0.1/3128; echo ping >&3; read -r line <&3; echo "got:$line"`)
	l, err := net.Listen("unix", filepath.Join(w.egress, EgressSocket))
	if err != nil {
		t.Skipf("this host does not let tests create Unix sockets: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 5)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write(append([]byte("pong:"), append(buf[:4], '\n')...))
			}()
		}
	}()
	stdout, stderr, code := run(t, n, w.spec, "")
	assert.Zero(t, code, stderr)
	assert.Contains(t, stdout, "got:pong:ping")
}
