package contained

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

// Native starts children with Go-native namespaces, Landlock and seccomp. It
// needs no helper beyond the keylatch binary itself.
type Native struct {
	// Binary is the keylatch executable that is re-executed as the helper. It
	// must call MaybeRun first thing in main.
	Binary string
	// Cgroups places each run in its own cgroup v2 leaf under the cgroup of
	// the calling process. A host that does not delegate one still runs, and
	// the audit trail records that the limits were not applied.
	Cgroups bool
}

const namespaceFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC |
	syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET | syscall.CLONE_NEWCGROUP

type child struct {
	cmd    *exec.Cmd
	cg     *cgroup
	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader
	master *os.File
	done   chan struct{}
	exit   int
	err    error
	once   sync.Once
}

// Start launches spec in a new sandbox.
func (n *Native) Start(spec Spec) (_ Child, retErr error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if n.Binary == "" {
		return nil, errors.New("contained: no helper binary is configured")
	}
	cfg, err := json.Marshal(initConfig{Spec: spec, Helper: n.Binary})
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			clear(cfg)
		}
	}()

	c := &child{done: make(chan struct{})}
	cmd := exec.Command(n.Binary)
	cmd.Args = []string{InitArg0}
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  namespaceFlags,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	if n.Cgroups {
		if parent, err := ownCgroup("/proc/self/cgroup", cgroupRoot); err == nil {
			if cg, err := newCgroup(parent, spec.Limits); err == nil {
				c.cg = cg
				cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, cg.FD()
			}
		}
	}
	closers, err := c.wireStdio(cmd, spec)
	if err != nil {
		c.cleanup()
		return nil, err
	}
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		c.cleanup()
		closers.close()
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{cfgR}
	c.cmd = cmd

	started := make(chan error, 1)
	go func() {
		// Pdeathsig fires when the thread that forked the child exits, so that
		// thread must outlive the run.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		_ = cfgR.Close()
		closers.close()
		started <- err
		if err != nil {
			return
		}
		c.exit, c.err = exitStatus(cmd.Wait())
		c.cleanup()
		close(c.done)
	}()
	if err := <-started; err != nil {
		_ = cfgW.Close()
		c.cleanup()
		return nil, fmt.Errorf("contained: start the sandbox (%s): %w", hint(err), err)
	}
	go func() {
		_, _ = cfgW.Write(cfg)
		_ = cfgW.Close()
		clear(cfg)
	}()
	return c, nil
}

func hint(err error) string {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
		return "unprivileged user namespaces may be disabled; run `keylatch doctor --sandbox`"
	}
	return "see `keylatch doctor --sandbox`"
}

// fdSet holds the child-side descriptors the parent closes after the start.
type fdSet []*os.File

func (s fdSet) close() {
	for _, f := range s {
		_ = f.Close()
	}
}

func (c *child) wireStdio(cmd *exec.Cmd, spec Spec) (fdSet, error) {
	if spec.TTY != nil {
		master, slave, err := openPTY(*spec.TTY)
		if err != nil {
			return nil, err
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, true, 0
		c.master, c.stdin, c.stdout = master, keepOpen{master}, ptyReader{master}
		return fdSet{slave}, nil
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		for _, f := range []*os.File{inR, inW, outR, outW} {
			_ = f.Close()
		}
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	c.stdin, c.stdout, c.stderr = inW, outR, errR
	return fdSet{inR, outW, errW}, nil
}

func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code, nil
		}
		return 128 + int(syscall.SIGKILL), nil
	}
	return 0, err
}

func (c *child) cleanup() {
	c.once.Do(func() {
		if c.cg != nil {
			c.cg.Kill()
			c.cg.Remove()
		}
	})
}

func (c *child) Stdin() io.WriteCloser { return c.stdin }
func (c *child) Stdout() io.Reader     { return c.stdout }
func (c *child) Stderr() io.Reader     { return c.stderr }

func (c *child) Resize(rows, cols uint16) error {
	if c.master == nil {
		return errors.New("contained: the run has no terminal")
	}
	return setWinsize(c.master, Winsize{Rows: rows, Cols: cols})
}

func (c *child) Signal(sig int) error {
	if c.cmd.Process == nil {
		return errors.New("contained: not started")
	}
	return c.cmd.Process.Signal(syscall.Signal(sig))
}

func (c *child) Kill() {
	if c.cg != nil {
		c.cg.Kill()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

func (c *child) Wait() (int, error) {
	<-c.done
	return c.exit, c.err
}
