package contained

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// hostHooks adapt a host process to the platform that confines it.
type hostHooks struct {
	// signal delivers sig to the run's processes.
	signal func(p *os.Process, sig int) error
	// kill ends every process of the run.
	kill func(p *os.Process)
	// cleanup runs once the run has ended.
	cleanup func()
}

// hostChild is a Child that is an ordinary host process the platform confined
// from outside (a Seatbelt profile) rather than from within.
type hostChild struct {
	cmd    *exec.Cmd
	hooks  hostHooks
	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader
	done   chan struct{}
	exit   int
	err    error
	once   sync.Once
}

// startHostCmd starts cmd with piped standard streams and returns it as a Child.
func startHostCmd(cmd *exec.Cmd, hooks hostHooks) (Child, error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	c := &hostChild{cmd: cmd, hooks: hooks, stdin: inW, stdout: outR, stderr: errR, done: make(chan struct{})}
	err = cmd.Start()
	closeAll(inR, outW, errW)
	if err != nil {
		closeAll(inW, outR, errR)
		c.finish()
		return nil, fmt.Errorf("contained: start the sandbox: %w", err)
	}
	go func() {
		c.exit, c.err = hostExitStatus(cmd.Wait())
		c.finish()
		close(c.done)
	}()
	return c, nil
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

func (c *hostChild) finish() {
	c.once.Do(func() {
		if c.hooks.cleanup != nil {
			c.hooks.cleanup()
		}
	})
}

func hostExitStatus(err error) (int, error) {
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

func (c *hostChild) Stdin() io.WriteCloser { return c.stdin }
func (c *hostChild) Stdout() io.Reader     { return c.stdout }
func (c *hostChild) Stderr() io.Reader     { return c.stderr }

func (*hostChild) Resize(uint16, uint16) error {
	return errors.New("contained: the run has no terminal")
}

func (c *hostChild) Signal(sig int) error {
	if c.cmd.Process == nil {
		return errors.New("contained: not started")
	}
	return c.hooks.signal(c.cmd.Process, sig)
}

func (c *hostChild) Kill() {
	if c.cmd.Process != nil {
		c.hooks.kill(c.cmd.Process)
	}
}

func (c *hostChild) Wait() (int, error) {
	<-c.done
	return c.exit, c.err
}

// lookPathIn resolves name against the PATH entries of env, the way the target
// would be found inside the sandbox. A name with a separator is used as given.
func lookPathIn(env []string, name string, exts []string) (string, error) {
	if strings.ContainsAny(name, `/\`) {
		return name, nil
	}
	var path string
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && strings.EqualFold(k, "PATH") {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		for _, ext := range append([]string{""}, exts...) {
			p := filepath.Join(dir, name+ext)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("contained: %q not found on the sandbox PATH", name)
}

// replaceEnv sets name to value in env, replacing an existing entry.
func replaceEnv(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); k != name {
			out = append(out, e)
		}
	}
	return append(out, name+"="+value)
}

// writeHoney writes the decoy files under home.
func writeHoney(home string, honey []HoneyFile) error {
	for _, h := range honey {
		p := filepath.Join(home, h.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(h.Content), 0o600); err != nil {
			return err
		}
	}
	return nil
}
