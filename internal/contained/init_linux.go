package contained

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Names the launcher gives the helper's two stages. The first is the
// namespace's init, the second applies the restrictions and becomes the target.
const (
	InitArg0  = "keylatch-sandbox-init"
	StageArg0 = "keylatch-sandbox-exec"

	// configFD is the inherited pipe that carries the initConfig.
	configFD = 3

	exitSetupFailed = 125
	exitExecFailed  = 126
	exitNotFound    = 127
)

// initConfig is what the launcher sends the helper over the pipe.
type initConfig struct {
	Spec Spec `json:"spec"`
	// Helper is the host path of the binary, bind-mounted into the new root so
	// the second stage can start after the root is replaced.
	Helper string `json:"helper"`
}

// MaybeRun runs the sandbox helper when the process was started as one and
// never returns in that case. Otherwise it returns false at once. The binary
// that hosts the launcher calls it first thing in main.
func MaybeRun() bool {
	switch filepath.Base(os.Args[0]) {
	case InitArg0:
		os.Exit(runInit(hostInit(), os.Stderr))
	case StageArg0:
		os.Exit(runStage(hostRestrictor{}, os.Stderr))
	}
	return false
}

func readConfig(f *os.File) (cfg initConfig, raw []byte, err error) {
	defer func() { _ = f.Close() }()
	raw, err = io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return cfg, nil, fmt.Errorf("read configuration: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, nil, fmt.Errorf("parse configuration: %w", err)
	}
	if err := cfg.Spec.Validate(); err != nil {
		return cfg, nil, err
	}
	return cfg, raw, nil
}

// runInit is the namespace's PID 1: it builds the root, brings up loopback,
// starts the forwarder, runs the second stage and reaps everything.
func runInit(d initDeps, stderr io.Writer) int {
	fail := func(what string, err error) int {
		fmt.Fprintf(stderr, "keylatch sandbox: %s: %v\n", what, err)
		return exitSetupFailed
	}
	if d.pid != 1 {
		fmt.Fprintln(stderr, "keylatch sandbox: the init stage runs only as PID 1 of a new namespace")
		return exitSetupFailed
	}
	cfg, raw, err := readConfig(d.config)
	if err != nil {
		return fail("configuration", err)
	}
	defer clear(raw)
	d.hide()

	if err := setupRoot(d.sys, cfg.Spec, cfg.Helper); err != nil {
		return fail("set up the root", err)
	}
	if err := d.sys.SetHostname("keylatch"); err != nil {
		return fail("set hostname", err)
	}
	if err := d.sys.LoopbackUp(); err != nil {
		return fail("bring up loopback", err)
	}
	l, err := d.listen(net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Spec.ProxyPort)))
	if err != nil {
		return fail("forwarder", err)
	}
	go Forward(l, d.dial)

	pid, err := d.startStage(raw)
	if err != nil {
		return fail("start the command", err)
	}
	return d.reap(pid)
}

// initDeps are the process-level collaborators of runInit.
type initDeps struct {
	sys    sysCalls
	pid    int
	config *os.File
	// hide makes the process unreadable to others in the namespace, so the
	// secrets it holds cannot be read from /proc.
	hide       func()
	listen     func(addr string) (net.Listener, error)
	dial       func() (net.Conn, error)
	startStage func(raw []byte) (int, error)
	reap       func(child int) int
}

func hostInit() initDeps {
	socket := filepath.Join(EgressMount, EgressSocket)
	return initDeps{
		sys:    hostSys{},
		pid:    os.Getpid(),
		config: os.NewFile(configFD, "config"),
		hide:   func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) },
		listen: func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) },
		dial:   func() (net.Conn, error) { return net.Dial("unix", socket) },
		startStage: func(raw []byte) (int, error) {
			return startStage(initBinaryPath, raw)
		},
		reap: func(child int) int { return reap(child, func() { _ = syscall.Kill(-1, syscall.SIGKILL) }) },
	}
}

// startStage forks the second stage with the configuration on a fresh pipe.
func startStage(binary string, raw []byte) (int, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer func() { _ = r.Close() }()
	pid, err := syscall.ForkExec(binary, []string{StageArg0}, &syscall.ProcAttr{
		Env:   []string{},
		Files: []uintptr{0, 1, 2, r.Fd()},
		Sys:   &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	})
	if err != nil {
		_ = w.Close()
		return 0, err
	}
	go func() {
		_, _ = w.Write(raw)
		_ = w.Close()
	}()
	return pid, nil
}

// reap waits for every process of the namespace. When the command ends, the
// rest are killed, so nothing outlives the run, and the command's status is
// the namespace's.
func reap(child int, killAll func()) int {
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			if sig, ok := s.(syscall.Signal); ok {
				_ = syscall.Kill(child, sig)
			}
		}
	}()
	code := exitSetupFailed
	killed := false
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return code
		}
		if pid != child {
			continue
		}
		code = statusCode(ws)
		if !killed {
			killed = true
			killAll()
		}
	}
}

func statusCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// runStage restricts the calling thread and replaces the process with the
// command. It returns only on failure, with the exit status to use.
func runStage(r restrictor, stderr io.Writer) int {
	if os.Getppid() != 1 {
		fmt.Fprintln(stderr, "keylatch sandbox: the exec stage runs only under the sandbox init")
		return exitSetupFailed
	}
	cfg, _, err := readConfig(os.NewFile(configFD, "config"))
	if err != nil {
		fmt.Fprintln(stderr, "keylatch sandbox:", err)
		return exitSetupFailed
	}
	// Landlock, seccomp and no_new_privs belong to a thread; exec keeps the
	// calling thread's, so the whole sequence stays on one.
	runtime.LockOSThread()
	return execTarget(r, cfg.Spec, syscall.Exec, stderr)
}

func execTarget(r restrictor, spec Spec, execve func(string, []string, []string) error, stderr io.Writer) int {
	path, ok := lookPath(spec.Env, spec.Argv[0])
	if err := unix.Chdir(spec.Dir); err != nil {
		fmt.Fprintf(stderr, "keylatch sandbox: working directory %s: %v\n", spec.Dir, err)
		return exitSetupFailed
	}
	if err := restrict(r, spec); err != nil {
		fmt.Fprintln(stderr, "keylatch sandbox:", err)
		return exitSetupFailed
	}
	if !ok {
		fmt.Fprintf(stderr, "keylatch sandbox: %s: command not found\n", spec.Argv[0])
		return exitNotFound
	}
	err := execve(path, spec.Argv, spec.Env)
	fmt.Fprintf(stderr, "keylatch sandbox: %s: %v\n", spec.Argv[0], err)
	if errors.Is(err, syscall.ENOENT) {
		return exitNotFound
	}
	return exitExecFailed
}

// lookPath resolves name against the PATH in env, inside the new root.
func lookPath(env []string, name string) (string, bool) {
	if strings.Contains(name, "/") {
		return name, true
	}
	pathVar := "/usr/local/bin:/usr/bin:/bin"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			pathVar = v
		}
	}
	for _, dir := range filepath.SplitList(pathVar) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}
