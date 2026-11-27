package contained

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const sandboxExec = "/usr/bin/sandbox-exec"

// Probe reports whether Seatbelt is available.
func Probe() Report {
	_, err := os.Stat(sandboxExec)
	return seatbeltReport(err)
}

// Start launches spec under a Seatbelt profile. The child reaches the network
// only through a forwarder on loopback that the profile names, so a run holds
// the forwarder's port for its lifetime.
func (n *Native) Start(spec Spec) (Child, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.TTY != nil {
		return nil, errors.New("contained: terminal runs are not supported on macOS")
	}
	home, tmp := hostDirs(spec)
	for _, d := range []string{home, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	if err := writeHoney(home, spec.Honey); err != nil {
		return nil, err
	}
	profile, err := SeatbeltProfile(seatbeltParams(spec, realDir))
	if err != nil {
		return nil, err
	}
	env := hostEnv(spec)
	target, err := lookPathIn(env, spec.Argv[0], nil)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ProxyPort))
	if err != nil {
		return nil, fmt.Errorf("contained: the proxy port %d is in use: %w", spec.ProxyPort, err)
	}
	egress := filepath.Join(spec.EgressDir, EgressSocket)
	go Forward(l, func() (net.Conn, error) { return net.Dial("unix", egress) })

	cmd := exec.Command(sandboxExec, sandboxExecArgs(profile, target, spec.Argv)...) //nolint:gosec // G204: the sandbox binary is fixed, the target is the caller's command
	cmd.Env, cmd.Dir = env, spec.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child, err := startHostCmd(cmd, hostHooks{
		signal:  func(p *os.Process, sig int) error { return syscall.Kill(-p.Pid, syscall.Signal(sig)) },
		kill:    func(p *os.Process) { _ = syscall.Kill(-p.Pid, syscall.SIGKILL) },
		cleanup: func() { _ = l.Close(); _ = os.RemoveAll(home); _ = os.RemoveAll(tmp) },
	})
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	return child, nil
}

func realDir(p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return r
}
