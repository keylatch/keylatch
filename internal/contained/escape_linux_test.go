package contained

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretValue = "sk_live_ESCAPE-CANARY-0123456789abcdef"

// probeRun runs the test binary as the hostile child inside the sandbox and
// returns its report, its raw stdout and the exit status.
func probeRun(t *testing.T, w *world, extraEnv ...string) (report map[string]string, stdout string, code int) {
	t.Helper()
	n := requireNamespaces(t)
	exe, err := os.Executable()
	require.NoError(t, err)
	w.spec.Argv = []string{exe, "-test.run=^TestSandboxProbe$", "-test.count=1"}
	w.spec.ReadOnly = append(w.spec.ReadOnly, filepath.Dir(exe))
	w.spec.Env = append(w.spec.Env, "KEYLATCH_SANDBOX_PROBE=1", "KEYLATCH_PROBE_PROJECT="+w.project, "GOCOVERDIR=/tmp")
	w.spec.Env = append(w.spec.Env, extraEnv...)
	stdout, stderr, code := run(t, n, w.spec, "")
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "PROBE-RESULT "); ok {
			require.NoError(t, json.Unmarshal([]byte(rest), &report))
			for name, got := range report {
				if name != "environ" && name != "proc_environ" {
					t.Logf("%-28s %s", name, got)
				}
			}
			return report, stdout, code
		}
	}
	t.Fatalf("the probe printed no report (exit %d)\nstdout: %s\nstderr: %s", code, stdout, stderr)
	return nil, "", 0
}

// hostSink listens on the host's loopback, where only a sandbox that shares
// the host network could reach it.
type hostSink struct {
	addr string
	hits chan struct{}
}

func newHostSink(t *testing.T) *hostSink {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	s := &hostSink{addr: l.Addr().String(), hits: make(chan struct{}, 16)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.hits <- struct{}{}
			_ = c.Close()
		}
	}()
	return s
}

func (s *hostSink) hit() bool {
	select {
	case <-s.hits:
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}

func TestEscapeEnvironmentHoldsOnlyWhatWasInjected(t *testing.T) {
	t.Setenv("KEYLATCH_HOST_ONLY_SECRET", "host-only-value")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-host-value")
	w := newWorld(t)
	w.spec.Env = append(w.spec.Env, "STRIPE_API_KEY="+secretValue)
	report, _, code := probeRun(t, w)
	require.Zero(t, code)
	for _, dump := range []string{report["environ"], report["proc_environ"]} {
		assert.Contains(t, dump, "STRIPE_API_KEY="+secretValue, "the injected value is the one thing the child holds")
		assert.NotContains(t, dump, "host-only-value")
		assert.NotContains(t, dump, "aws-host-value")
		assert.NotContains(t, dump, "SSH_AUTH_SOCK")
	}
}

func TestEscapeSyscallsAreDenied(t *testing.T) {
	report, _, code := probeRun(t, newWorld(t))
	require.Zero(t, code)
	for name, got := range report {
		switch name {
		case "environ", "proc_environ", "interfaces":
			continue
		}
		if !strings.Contains(name, "ptrace") && !strings.Contains(name, "_") && !strings.HasPrefix(name, "unshare") &&
			!strings.HasPrefix(name, "clone") && !strings.HasPrefix(name, "mount") && !strings.HasPrefix(name, "umount") &&
			name != "setns" && name != "pivot_root" && name != "chroot" && name != "reboot" && name != "keyctl" && name != "bpf" &&
			name != "swapon" && name != "fsopen" {
			continue
		}
		assert.NotEqual(t, "ok", got, "%s must not succeed inside the sandbox", name)
	}
	for _, name := range []string{"ptrace", "process_vm_readv", "process_vm_writev", "keyctl", "add_key", "bpf", "perf_event_open",
		"userfaultfd", "io_uring_setup", "unshare newuser", "unshare newns", "setns", "pivot_root", "mount tmpfs", "umount /proc",
		"clone newuser", "kexec_load", "init_module", "reboot", "fsopen", "mount_setattr", "pidfd_getfd", "clone3 newuser", "chroot"} {
		got, ok := report[name]
		require.True(t, ok, "the probe did not try %s", name)
		assert.Contains(t, []string{"operation not permitted", "function not implemented"}, got, "%s: %s", name, got)
	}
}

func TestEscapeNetworkReachesNothing(t *testing.T) {
	sink := newHostSink(t)
	_, port, err := net.SplitHostPort(sink.addr)
	require.NoError(t, err)
	p, _ := strconv.Atoi(port)
	w := newWorld(t)
	report, _, code := probeRun(t, w,
		"KEYLATCH_PROBE_HOST_SINK="+sink.addr,
		"KEYLATCH_PROBE_HOST_SINK_DECIMAL=2130706433:"+port,
		"KEYLATCH_PROBE_HOST_SINK_HEX=0x7f000001:"+port,
	)
	require.Zero(t, code)
	assert.False(t, sink.hit(), "the host loopback listener (port %d) must see no connection", p)
	for name, got := range report {
		if strings.HasPrefix(name, "tcp ") || strings.HasPrefix(name, "udp ") {
			assert.Equal(t, "failed", got, name)
		}
	}
	assert.Equal(t, "true", report["dns lookup"], "no name resolves without the proxy")
	assert.Equal(t, "lo", report["interfaces"], "the namespace has only loopback")
	assert.NotEqual(t, "ok", report["icmp socket"])
}

func TestEscapeStateAndCredentialStoresAreAbsent(t *testing.T) {
	w := newWorld(t)
	base := filepath.Dir(w.project)
	state := filepath.Join(base, "state", "keyring")
	ssh := filepath.Join(base, "home", ".ssh", "id_ed25519")
	for _, p := range []string{state, ssh} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(secretValue), 0o600))
	}
	report, stdout, code := probeRun(t, w, "KEYLATCH_PROBE_STATE="+state, "KEYLATCH_PROBE_SSH="+ssh,
		"KEYLATCH_PROBE_HOSTPROC=/proc/"+strconv.Itoa(os.Getpid())+"/environ")
	require.Zero(t, code)
	for _, name := range []string{"read KEYLATCH_PROBE_STATE", "read KEYLATCH_PROBE_SSH", "symlink to state", "dotdot to state", "proc self root"} {
		assert.NotEqual(t, "ok", report[name], name)
	}
	assert.NotContains(t, stdout, secretValue)
	assert.NotEqual(t, "ok", report["read KEYLATCH_PROBE_HOSTPROC"], "the host's processes are not in this PID namespace")
	assert.NotEqual(t, "ok", report["hardlink to /etc/passwd"])
	assert.NotEqual(t, "ok", report["write /usr"])
	assert.NotEqual(t, "ok", report["write /etc"])
	assert.NotEqual(t, "ok", report["read /proc/1/mem"])
	assert.NotEqual(t, "ok", report["read /proc/1/environ"])
	assert.NotEqual(t, "ok", report["write /proc/sys"])
	assert.Equal(t, "ok", report["write project"], "the project directory is the one writable place")
}

func TestEscapeDaemonizedChildrenDieWithTheRun(t *testing.T) {
	w := newWorld(t)
	started := time.Now()
	report, _, code := probeRun(t, w, "KEYLATCH_PROBE_DAEMONIZE=1")
	require.Zero(t, code)
	assert.NotEmpty(t, report)
	// run waits for the output pipes to close; a surviving `sleep 600`
	// holding them would have made it block until the test timeout.
	assert.Less(t, time.Since(started), 30*time.Second)
}

func TestEscapeProjectWritesAreScannableByTheHost(t *testing.T) {
	w := newWorld(t)
	_, _, code := probeRun(t, w, "KEYLATCH_PROBE_WRITE="+secretValue)
	require.Zero(t, code)
	b, err := os.ReadFile(filepath.Join(w.project, "written"))
	require.NoError(t, err)
	assert.Equal(t, secretValue, string(b))
}
