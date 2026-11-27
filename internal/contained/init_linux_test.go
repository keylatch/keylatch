package contained

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configFile(t *testing.T, spec Spec) *os.File {
	t.Helper()
	raw, err := json.Marshal(initConfig{Spec: spec, Helper: "/usr/bin/keylatch"})
	require.NoError(t, err)
	r, w, err := os.Pipe()
	require.NoError(t, err)
	go func() { _, _ = w.Write(raw); _ = w.Close() }()
	return r
}

type initRecorder struct {
	sys        *fakeSys
	staged     []byte
	reaped     int
	listenAddr string
	dialed     chan struct{}
}

func newInitDeps(t *testing.T) (initDeps, *initRecorder) {
	t.Helper()
	rec := &initRecorder{sys: &fakeSys{missing: map[string]bool{}}, dialed: make(chan struct{}, 1)}
	return initDeps{
		sys:    rec.sys,
		pid:    1,
		hide:   func() {},
		config: configFile(t, testSpec()),
		listen: func(addr string) (net.Listener, error) {
			rec.listenAddr = addr
			return net.Listen("tcp", "127.0.0.1:0")
		},
		dial: func() (net.Conn, error) {
			rec.dialed <- struct{}{}
			return nil, errors.New("no upstream in this test")
		},
		startStage: func(raw []byte) (int, error) {
			rec.staged = append([]byte(nil), raw...)
			return 77, nil
		},
		reap: func(child int) int { rec.reaped = child; return 9 },
	}, rec
}

func TestRunInitAssemblesTheNamespaceAndHandsOverToTheCommand(t *testing.T) {
	d, rec := newInitDeps(t)
	var stderr bytes.Buffer
	assert.Equal(t, 9, runInit(d, &stderr), stderr.String())
	assert.Equal(t, 77, rec.reaped)
	assert.True(t, rec.sys.has("pivot "), "the root is replaced")
	assert.True(t, rec.sys.has("hostname keylatch"))
	assert.True(t, rec.sys.has("lo up"))
	assert.Equal(t, "127.0.0.1:3128", rec.listenAddr)
	var cfg initConfig
	require.NoError(t, json.Unmarshal(rec.staged, &cfg), "the second stage gets the whole configuration")
	assert.Equal(t, testSpec().Argv, cfg.Spec.Argv)
}

func TestRunInitStopsAtTheFirstFailure(t *testing.T) {
	for _, tc := range []struct{ name, failOn, want string }{
		{"root", "pivot", "set up the root"},
		{"hostname", "hostname", "set hostname"},
		{"loopback", "lo up", "bring up loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, rec := newInitDeps(t)
			rec.sys.failOn = tc.failOn
			var stderr bytes.Buffer
			assert.Equal(t, exitSetupFailed, runInit(d, &stderr))
			assert.Contains(t, stderr.String(), tc.want)
			assert.Zero(t, rec.reaped)
		})
	}

	d, _ := newInitDeps(t)
	d.listen = func(string) (net.Listener, error) { return nil, errors.New("in use") }
	var stderr bytes.Buffer
	assert.Equal(t, exitSetupFailed, runInit(d, &stderr))
	assert.Contains(t, stderr.String(), "forwarder")

	d, _ = newInitDeps(t)
	d.startStage = func([]byte) (int, error) { return 0, errors.New("no such file") }
	stderr.Reset()
	assert.Equal(t, exitSetupFailed, runInit(d, &stderr))
	assert.Contains(t, stderr.String(), "start the command")

	d, _ = newInitDeps(t)
	d.config = configFile(t, Spec{})
	stderr.Reset()
	assert.Equal(t, exitSetupFailed, runInit(d, &stderr))
	assert.Contains(t, stderr.String(), "configuration")
}

func TestForwarderDialsTheEgressSocketPerConnection(t *testing.T) {
	d, rec := newInitDeps(t)
	var l net.Listener
	d.listen = func(string) (net.Listener, error) {
		var err error
		l, err = net.Listen("tcp", "127.0.0.1:0")
		return l, err
	}
	require.Equal(t, 9, runInit(d, &bytes.Buffer{}))
	defer func() { _ = l.Close() }()
	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	select {
	case <-rec.dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the forwarder did not dial the egress socket")
	}
}

func TestHostInitWiresTheEgressSocketPath(t *testing.T) {
	d := hostInit()
	defer func() { _ = d.config.Close() }()
	assert.NotNil(t, d.sys)
	_, err := d.dial()
	assert.Error(t, err, "there is no egress socket outside the sandbox")
	l, err := d.listen("127.0.0.1:0")
	require.NoError(t, err)
	_ = l.Close()
}

func TestStartStagePassesTheConfigurationOnFD3(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "got")
	script := filepath.Join(dir, "stage")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nexec cat <&3 > "+out+"\n"), 0o755))
	pid, err := startStage(script, []byte(`{"hello":"world"}`))
	require.NoError(t, err)
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	require.NoError(t, err)
	assert.Zero(t, ws.ExitStatus())
	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.JSONEq(t, `{"hello":"world"}`, string(b))

	_, err = startStage(filepath.Join(dir, "missing"), nil)
	assert.Error(t, err)
}

func TestReapReturnsTheCommandStatusAndKillsTheRest(t *testing.T) {
	pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "exit 17"}, &syscall.ProcAttr{})
	if err != nil {
		t.Skipf("no /bin/sh to fork: %v", err)
	}
	killed := 0
	code := reap(pid, func() { killed++ })
	assert.Equal(t, 17, code)
	assert.Equal(t, 1, killed, "the rest of the namespace is killed exactly once")
}

func TestReapReportsASignalDeath(t *testing.T) {
	pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "kill -9 $$"}, &syscall.ProcAttr{})
	if err != nil {
		t.Skipf("no /bin/sh to fork: %v", err)
	}
	assert.Equal(t, 128+9, reap(pid, func() {}))
}

func TestReapWithNoChildrenReportsSetupFailure(t *testing.T) {
	assert.Equal(t, exitSetupFailed, reap(999999, func() { t.Fatal("nothing ran, so nothing is killed") }))
}
