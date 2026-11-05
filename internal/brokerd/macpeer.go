package brokerd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/control"
)

// auditToken is the audit_token_t the kernel attaches to a Unix socket peer
// (LOCAL_PEERTOKEN): audit uid, euid, egid, ruid, rgid, pid, session, and the
// PID version that changes when a PID is reused. Reading the token at connect
// time, together with the start time, pins the process.
type auditToken [8]uint32

func (t auditToken) euid() uint32 { return t[1] }
func (t auditToken) pid() int     { return int(t[5]) } //nolint:gosec // G115: a PID fits an int

// macProc is what the daemon reads about a process from the kernel.
type macProc struct {
	// Start is the process start time as seconds.microseconds since the epoch.
	Start string
	PPID  int
	Exe   string
}

// macSystem is the set of kernel calls macOS peer identification makes; tests
// replace it.
type macSystem interface {
	// PeerUID returns the effective uid the peer connected with (LOCAL_PEERCRED).
	PeerUID(control.Conn) (uint32, error)
	PeerPID(control.Conn) (int, error)
	PeerToken(control.Conn) (auditToken, error)
	Process(pid int) (macProc, error)
}

// CodeResolver names the code identity of a running process.
type CodeResolver interface {
	Identity(ctx context.Context, pid int, exe string) (string, error)
}

// MacIdentifier identifies socket peers with the audit token, which names the
// process and its PID version, and pins them by start time.
type MacIdentifier struct {
	Sys  macSystem
	Code CodeResolver
}

// ErrTokenMismatch means LOCAL_PEERPID, LOCAL_PEERCRED and LOCAL_PEERTOKEN do not
// describe the same process.
var ErrTokenMismatch = errors.New("brokerd: the peer's audit token does not match its credentials")

// Identify implements the Config.Identify contract.
func (m MacIdentifier) Identify(c control.Conn) (*Identity, error) {
	uid, err := m.Sys.PeerUID(c)
	if err != nil {
		return nil, err
	}
	pid, err := m.Sys.PeerPID(c)
	if err != nil {
		return nil, err
	}
	if pid <= 0 {
		return nil, ErrNoPID
	}
	tok, err := m.Sys.PeerToken(c)
	if err != nil {
		return nil, err
	}
	if tok.pid() != pid || tok.euid() != uid {
		return nil, ErrTokenMismatch
	}
	proc, err := m.Sys.Process(pid)
	if err != nil {
		return nil, errors.Join(ErrPeerGone, err)
	}
	id := &Identity{UID: uid, PID: pid, Start: proc.Start, Exe: proc.Exe, ParentPID: proc.PPID, pin: &macPin{sys: m.Sys}}
	if m.Code != nil && proc.Exe != "" {
		// A binary that cannot be read for its signature has no code identity;
		// rules that need one then fail closed.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if code, err := m.Code.Identity(ctx, pid, proc.Exe); err == nil {
			id.Code = code
		}
	}
	if err := id.Verify(); err != nil {
		return nil, err
	}
	return id, nil
}

type macPin struct{ sys macSystem }

func (p *macPin) verify(id *Identity) error {
	proc, err := p.sys.Process(id.PID)
	if err != nil {
		return errors.Join(ErrPeerGone, err)
	}
	if proc.Start != id.Start || proc.PPID != id.ParentPID {
		return ErrPeerGone
	}
	return nil
}

func (*macPin) close() {}

// CodeIdentity is what codesign reports about a signed binary.
type CodeIdentity struct {
	Identifier string
	Team       string
	CDHash     string
}

// String is the form Identity.Code carries and enrollment pins.
func (c CodeIdentity) String() string {
	return "team=" + c.Team + ";id=" + c.Identifier
}

// ParseCodesign reads the output of `codesign -d --verbose=4`.
func ParseCodesign(out string) (CodeIdentity, error) {
	var c CodeIdentity
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Identifier":
			c.Identifier = v
		case "TeamIdentifier":
			if v != "not set" {
				c.Team = v
			}
		case "CDHash":
			c.CDHash = v
		}
	}
	if c.Identifier == "" {
		return c, errors.New("brokerd: the binary is not code signed")
	}
	return c, nil
}

// codesignBin is fixed: the PATH belongs to the caller.
const codesignBin = "/usr/bin/codesign"

// Codesign resolves and checks code identities with the codesign tool. Results
// are cached by executable path, size and modification time.
type Codesign struct {
	Run Runner
	// Stat reports a file's size and modification time; nil uses the file system.
	Stat func(path string) (size int64, mod time.Time, err error)

	mu    sync.Mutex
	cache map[string]string
}

// Identity implements CodeResolver.
func (c *Codesign) Identity(ctx context.Context, _ int, exe string) (string, error) {
	key := exe
	if c.Stat != nil {
		if size, mod, err := c.Stat(exe); err == nil {
			key = exe + "|" + strconv.FormatInt(size, 10) + "|" + strconv.FormatInt(mod.UnixNano(), 10)
		}
	}
	c.mu.Lock()
	if v, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	out, err := c.Run.Run(ctx, nil, codesignBin, "-d", "--verbose=4", exe)
	// codesign reports on stderr and exits 1 for an unsigned binary.
	ci, perr := ParseCodesign(string(out))
	if perr != nil {
		return "", errors.Join(perr, err)
	}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]string{}
	}
	c.cache[key] = ci.String()
	c.mu.Unlock()
	return ci.String(), nil
}

// Satisfies reports whether the running process pid (or, without one, the
// binary at exe) meets the designated requirement. The check runs against the
// live process so a binary replaced after launch does not pass.
func (c *Codesign) Satisfies(ctx context.Context, pid int, exe, requirement string) error {
	target := exe
	if pid > 0 {
		target = "+" + strconv.Itoa(pid)
	}
	if _, err := c.Run.Run(ctx, nil, codesignBin, "--verify", "--strict", "-R", "="+requirement, target); err != nil {
		return fmt.Errorf("brokerd: %s does not satisfy the requirement: %w", target, err)
	}
	return nil
}

// DesignatedRequirement returns the designated requirement of the binary at
// path, the text enrollment pins.
func (c *Codesign) DesignatedRequirement(ctx context.Context, path string) (string, error) {
	out, err := c.Run.Run(ctx, nil, codesignBin, "-d", "-r-", path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if req, ok := strings.CutPrefix(strings.TrimSpace(line), "designated => "); ok {
			return req, nil
		}
	}
	return "", errors.New("brokerd: the binary has no designated requirement")
}
