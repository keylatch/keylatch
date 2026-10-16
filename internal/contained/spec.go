// Package contained runs a command inside a Keylatch sandbox, the delivery
// tier that hands a child the real secret value. The child lives in new user,
// mount, PID, IPC, UTS, network and cgroup namespaces with a private root,
// Landlock rules, a seccomp filter and a cgroup leaf. Its only way out of the
// network namespace is a forwarder that reaches the daemon's egress proxy over
// a Unix socket.
//
// The launcher re-executes the keylatch binary twice inside the namespaces:
// first as the namespace's init (mounts, loopback, forwarder, reaping), then
// as a stage that applies the restrictions on one OS thread and replaces itself
// with the target command. Secrets travel over an inherited pipe and appear
// only in the target's environment block.
package contained

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const (
	// DefaultProxyPort is the loopback port the in-namespace forwarder listens on.
	DefaultProxyPort = 3128
	// DefaultHome is the synthetic home directory of the child.
	DefaultHome = "/home/keylatch"
	// EgressSocket is the file name of the daemon's egress socket inside the
	// directory Spec.EgressDir.
	EgressSocket = "egress.sock"
	// EgressMount is where Spec.EgressDir appears inside the sandbox.
	EgressMount = "/run/keylatch"
)

// ErrUnsupported is returned where the sandbox cannot run.
var ErrUnsupported = errors.New("contained: the Keylatch sandbox is not available on this platform")

// Limits bound what a run may consume. Zero values leave a limit unset.
type Limits struct {
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	PIDs        int   `json:"pids,omitempty"`
	// CPUPercent is a share of one CPU.
	CPUPercent int `json:"cpu_percent,omitempty"`
}

// Winsize is the size of the terminal a PTY run starts with.
type Winsize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// HoneyFile is a decoy credential file.
type HoneyFile struct {
	// Path is relative to the home directory and must stay inside it.
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Spec describes one contained run.
type Spec struct {
	// Argv is the command; Argv[0] is looked up on the PATH in Env, or used as
	// given when it contains a slash.
	Argv []string `json:"argv"`
	// Env is the child's complete environment as NAME=VALUE entries. It is the
	// only place secret values appear, and it travels over a pipe.
	Env []string `json:"env"`
	// Dir is the working directory inside the sandbox; it defaults to Project.
	Dir string `json:"dir,omitempty"`
	// Project is the read-write project directory, an absolute real path that
	// appears at the same path inside the sandbox.
	Project string `json:"project"`
	// ReadOnly and ReadWrite are further host paths that appear at the same
	// path inside the sandbox. Paths that do not exist are skipped.
	ReadOnly  []string `json:"read_only,omitempty"`
	ReadWrite []string `json:"read_write,omitempty"`
	// Home is the empty tmpfs home directory; it defaults to DefaultHome.
	Home string `json:"home,omitempty"`
	// EgressDir is the host directory holding EgressSocket. It appears at
	// EgressMount.
	EgressDir string `json:"egress_dir"`
	// RootDir is an empty host directory, private to the daemon, on which the
	// new root is assembled.
	RootDir string `json:"root_dir"`
	// ProxyPort is the loopback port of the forwarder; default DefaultProxyPort.
	ProxyPort int `json:"proxy_port,omitempty"`
	// ConnectPorts are further loopback ports the child may connect to.
	ConnectPorts []int `json:"connect_ports,omitempty"`
	// AllowIOUring lifts the default ban on io_uring.
	AllowIOUring bool `json:"allow_io_uring,omitempty"`
	// Honey are decoy credential files written into the empty home before the
	// command starts.
	Honey  []HoneyFile `json:"honey,omitempty"`
	Limits Limits      `json:"limits"`
	TTY    *Winsize    `json:"tty,omitempty"`
}

// Validate checks a Spec and fills in its defaults.
func (s *Spec) Validate() error {
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return errors.New("contained: a command is required")
	}
	for _, a := range s.Argv {
		if strings.ContainsRune(a, 0) {
			return errors.New("contained: argv contains a NUL byte")
		}
	}
	for _, e := range s.Env {
		name, _, ok := strings.Cut(e, "=")
		if !ok || name == "" || strings.ContainsRune(e, 0) {
			return fmt.Errorf("contained: malformed environment entry %q", name)
		}
	}
	for label, p := range map[string]string{"project": s.Project, "egress directory": s.EgressDir, "root directory": s.RootDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("contained: the %s must be a clean absolute path", label)
		}
	}
	for _, p := range append(append([]string{s.Dir, s.Home}, s.ReadOnly...), s.ReadWrite...) {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p) {
			return fmt.Errorf("contained: %q must be a clean absolute path", p)
		}
	}
	for _, h := range s.Honey {
		if h.Path == "" || !filepath.IsLocal(h.Path) {
			return fmt.Errorf("contained: honey file path %q must stay inside the home directory", h.Path)
		}
	}
	if s.Dir == "" {
		s.Dir = s.Project
	}
	if s.Home == "" {
		s.Home = DefaultHome
	}
	if s.ProxyPort == 0 {
		s.ProxyPort = DefaultProxyPort
	}
	for _, p := range append([]int{s.ProxyPort}, s.ConnectPorts...) {
		if p < 1 || p > 65535 {
			return fmt.Errorf("contained: port %d is out of range", p)
		}
	}
	if s.TTY != nil && (s.TTY.Rows == 0 || s.TTY.Cols == 0) {
		s.TTY = &Winsize{Rows: 24, Cols: 80}
	}
	return nil
}

// Child is a running contained command.
type Child interface {
	// Stdin feeds the child; closing it ends the child's standard input.
	Stdin() io.WriteCloser
	// Stdout is the child's output; for a PTY run it carries stderr too.
	Stdout() io.Reader
	// Stderr is nil for a PTY run.
	Stderr() io.Reader
	// Resize changes the size of the child's terminal.
	Resize(rows, cols uint16) error
	// Signal delivers a signal to the child's process group.
	Signal(sig int) error
	// Kill ends every process of the sandbox.
	Kill()
	// Wait blocks until the sandbox ends and returns the exit status; a child
	// ended by a signal reports 128 plus the signal number.
	Wait() (int, error)
}

// Launcher starts contained children.
type Launcher interface {
	Start(spec Spec) (Child, error)
}

// Capability is one row of a Report.
type Capability struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Report says what the host lets the sandbox do.
type Report struct {
	Backend string `json:"backend"`
	// Supported means every required capability is present, so D5 runs.
	Supported    bool         `json:"supported"`
	Capabilities []Capability `json:"capabilities"`
}

// Get returns a capability by name.
func (r Report) Get(name string) (Capability, bool) {
	for _, c := range r.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}

// Missing lists the required capabilities the host lacks.
func (r Report) Missing() []string {
	var out []string
	for _, c := range r.Capabilities {
		if !c.OK && requiredCapability[c.Name] {
			out = append(out, c.Name+": "+c.Detail)
		}
	}
	return out
}

// requiredCapability names the capabilities without which D5 refuses to run.
// Cgroup limits and the Landlock network rule are reported but optional: the
// namespaces and the seccomp filter already confine the child.
var requiredCapability = map[string]bool{
	"user_namespace":  true,
	"mount_namespace": true,
	"pid_namespace":   true,
	"net_namespace":   true,
	"seccomp":         true,
	"landlock":        true,
}
