package contained

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOwnCgroupReadsTheUnifiedHierarchyLine(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "cgroup")
	require.NoError(t, os.WriteFile(self, []byte("12:cpu:/legacy\n0::/user.slice/app.scope\n"), 0o644))
	got, err := ownCgroup(self, "/sys/fs/cgroup")
	require.NoError(t, err)
	assert.Equal(t, "/sys/fs/cgroup/user.slice/app.scope", got)

	require.NoError(t, os.WriteFile(self, []byte("0::/../../escape\n"), 0o644))
	got, err = ownCgroup(self, "/sys/fs/cgroup")
	require.NoError(t, err)
	assert.Equal(t, "/sys/fs/cgroup/escape", got, "a hostile path cannot leave the cgroup root")

	require.NoError(t, os.WriteFile(self, []byte("12:cpu:/legacy\n"), 0o644))
	_, err = ownCgroup(self, "/sys/fs/cgroup")
	assert.ErrorContains(t, err, "cgroup v2")
	_, err = ownCgroup(filepath.Join(dir, "missing"), "/")
	assert.Error(t, err)
}

func TestCgroupLeafAppliesLimitsAndKills(t *testing.T) {
	parent := t.TempDir()
	cg, err := newCgroup(parent, Limits{MemoryBytes: 1 << 30, PIDs: 64, CPUPercent: 50})
	require.NoError(t, err)
	assert.Contains(t, filepath.Base(cg.dir), "keylatch-run-")
	for file, want := range map[string]string{"memory.max": "1073741824", "pids.max": "64", "cpu.max": "50000 100000"} {
		b, err := os.ReadFile(filepath.Join(cg.dir, file))
		require.NoError(t, err)
		assert.Equal(t, want, string(b))
	}
	assert.Positive(t, cg.FD())
	assert.Empty(t, cg.Notes)

	// On a real cgroup the kill file ends everything at once. Make it
	// unwritable here so Kill falls back to signalling the listed processes.
	sleeper := exec.Command("sleep", "600")
	require.NoError(t, sleeper.Start())
	t.Cleanup(func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() })
	require.NoError(t, os.Mkdir(filepath.Join(cg.dir, "cgroup.kill"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cg.dir, "cgroup.procs"), []byte(strconv.Itoa(sleeper.Process.Pid)+"\nnot-a-pid\n"), 0o644))
	cg.Kill()
	assert.Error(t, sleeper.Wait(), "the process listed in the cgroup was killed")
	require.NoError(t, os.Remove(filepath.Join(cg.dir, "cgroup.kill")))
	cg.Kill()
	b, err := os.ReadFile(filepath.Join(cg.dir, "cgroup.kill"))
	require.NoError(t, err)
	assert.Equal(t, "1", string(b), "a writable kill file is how the kernel kills the group")
	cg.Remove()
}

func TestCgroupLimitFailuresAreNotes(t *testing.T) {
	parent := t.TempDir()
	require.NoError(t, os.Chmod(parent, 0o500))
	_, err := newCgroup(parent, Limits{})
	if os.Getuid() != 0 {
		assert.Error(t, err, "a parent that cannot be written to has no leaf")
	}
	_ = os.Chmod(parent, 0o700)

	_, err = newCgroup(filepath.Join(parent, "absent"), Limits{})
	assert.Error(t, err)
}

func TestExitStatusMapsProcessEnds(t *testing.T) {
	code, err := exitStatus(nil)
	assert.Zero(t, code)
	assert.NoError(t, err)

	runErr := exec.Command("sh", "-c", "exit 3").Run()
	code, err = exitStatus(runErr)
	assert.Equal(t, 3, code)
	assert.NoError(t, err)

	runErr = exec.Command("sh", "-c", "kill -9 $$").Run()
	code, err = exitStatus(runErr)
	assert.Equal(t, 137, code, "a process killed by a signal has no exit code")
	assert.NoError(t, err)

	_, err = exitStatus(errors.New("pipe broke"))
	assert.Error(t, err)
}

func TestPrivilegedHostCallsFailCleanlyWithoutPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: these calls would succeed")
	}
	h := hostSys{}
	assert.Error(t, h.SetHostname("keylatch-test"))
	// Loopback is already up outside a sandbox; reconfiguring it needs
	// CAP_NET_ADMIN.
	assert.Error(t, h.LoopbackUp())
}

func TestProbeReportsEachCapabilityFromItsSource(t *testing.T) {
	ok := func(uintptr) error { return nil }
	good := probeEnv{
		namespace: ok, landlock: func() int { return 6 }, seccomp: func() error { return nil },
		cgroup: func() ([]string, error) { return []string{"memory", "pids"}, nil },
		sysctl: func(string) string { return "" },
	}
	r := good.report()
	assert.True(t, r.Supported)
	assert.Equal(t, "native", r.Backend)
	assert.Empty(t, r.Missing())
	c, _ := r.Get("landlock")
	assert.Equal(t, "ABI 6", c.Detail)
	c, _ = r.Get("cgroup_leaf")
	assert.Contains(t, c.Detail, "memory,pids")

	noUserNS := good
	noUserNS.namespace = func(uintptr) error { return errors.New("operation not permitted") }
	noUserNS.sysctl = func(p string) string {
		if strings.HasSuffix(p, "max_user_namespaces") {
			return "0"
		}
		return "1"
	}
	r = noUserNS.report()
	assert.False(t, r.Supported)
	c, _ = r.Get("user_namespace")
	assert.Contains(t, c.Detail, "max_user_namespaces is 0")
	assert.Contains(t, c.Detail, "apparmor_restrict_unprivileged_userns")
	c, _ = r.Get("net_namespace")
	assert.Contains(t, c.Detail, "needs user_namespace")

	onlyNet := good
	onlyNet.namespace = func(f uintptr) error {
		if f == syscall.CLONE_NEWNET {
			return errors.New("denied")
		}
		return nil
	}
	assert.Contains(t, onlyNet.report().Missing()[0], "net_namespace")

	noLandlock := good
	noLandlock.landlock = func() int { return 0 }
	r = noLandlock.report()
	assert.False(t, r.Supported)
	c, _ = r.Get("landlock_network")
	assert.False(t, c.OK)

	oldLandlock := good
	oldLandlock.landlock = func() int { return 2 }
	r = oldLandlock.report()
	assert.True(t, r.Supported, "TCP rules are an optional layer")
	c, _ = r.Get("landlock_network")
	assert.Contains(t, c.Detail, "ABI 2")

	noCgroup := good
	noCgroup.cgroup = func() ([]string, error) { return nil, errors.New("read-only") }
	r = noCgroup.report()
	assert.True(t, r.Supported, "limits are optional")
	c, _ = r.Get("cgroup_leaf")
	assert.False(t, c.OK)

	noSeccomp := good
	noSeccomp.seccomp = func() error { return errors.New("no seccomp") }
	assert.False(t, noSeccomp.report().Supported)
}

func TestHostProbeRunsAgainstTheRealKernel(t *testing.T) {
	r := Probe()
	assert.Equal(t, "native", r.Backend)
	assert.NotEmpty(t, r.Capabilities)
	_, err := probeCgroup()
	_ = err // may be refused on hosts that do not delegate a cgroup
	assert.Error(t, tryNamespaceMissingTrue(t))
}

// tryNamespaceMissingTrue runs the namespace probe with no `true` binary on
// the PATH.
func tryNamespaceMissingTrue(t *testing.T) error {
	t.Setenv("PATH", t.TempDir())
	return tryNamespace(0)
}

func TestPTYReaderTurnsHangupIntoEOF(t *testing.T) {
	master, slave, err := openPTY(Winsize{Rows: 10, Cols: 20})
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	r := ptyReader{master}
	_, _ = slave.WriteString("hi")
	buf := make([]byte, 16)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.NotZero(t, n)
	require.NoError(t, slave.Close())
	for err == nil {
		_, err = r.Read(buf)
	}
	assert.ErrorContains(t, err, "EOF")

	m2, s2, err := openPTY(Winsize{Rows: 1, Cols: 1})
	require.NoError(t, err)
	_ = s2.Close()
	assert.NoError(t, ptyReader{m2}.Close())
	assert.NoError(t, keepOpen{m2}.Close())
}
