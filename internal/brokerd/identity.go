// Package brokerd is the system broker: a daemon under its own OS user that
// holds the key hierarchy, the secret store, the policy and the audit log, and
// answers clients on a Unix socket after proving who is on the other end.
//
// The wire protocol is the control protocol (JSON frames) extended with the
// broker operations in package brokerapi. gRPC would add a code-generation
// step and a second framing for no gain in security: the socket is local, the
// peer is identified by the kernel, and every frame is size-bounded and
// strictly decoded (and fuzzed). The daemon keeps the one protocol the thin
// client already speaks, so there is one client to audit.
package brokerd

import (
	"errors"
	"strings"
)

var (
	// ErrPeerGone means the process that opened the connection no longer
	// matches the identity recorded when it connected: it exited, and its PID
	// may have been reused.
	ErrPeerGone = errors.New("brokerd: the peer process no longer matches its identity")
	// ErrUnsupported means peer identity cannot be established on this platform.
	ErrUnsupported = errors.New("brokerd: peer identity is not supported on this platform")
	// ErrNoPID means the peer lives in a PID namespace the daemon cannot see.
	ErrNoPID = errors.New("brokerd: the peer is outside the daemon's PID namespace")
)

// Identity is the kernel-attested identity of a socket peer, pinned to the
// process with a pidfd so a recycled PID is detected.
type Identity struct {
	UID uint32
	PID int
	// Start is the process start time in clock ticks since boot (field 22 of
	// /proc/<pid>/stat).
	Start string
	// Cgroup is the process's control group path.
	Cgroup string

	pin pin
}

// Verify reports ErrPeerGone unless the connected process is still the process
// that was identified.
func (i *Identity) Verify() error {
	if i == nil || i.pin == nil {
		return ErrUnsupported
	}
	return i.pin.verify(i)
}

// Close releases the pidfd.
func (i *Identity) Close() {
	if i != nil && i.pin != nil {
		i.pin.close()
	}
}

// pin ties an Identity to a live process.
type pin interface {
	verify(*Identity) error
	close()
}

// ParseStartTime returns field 22 of a /proc/<pid>/stat dump, the process start
// time in clock ticks since boot.
func ParseStartTime(stat string) (string, error) {
	// comm may contain spaces and parentheses; the fields start after the last ')'.
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return "", errors.New("brokerd: malformed /proc stat")
	}
	fields := strings.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return "", errors.New("brokerd: short /proc stat")
	}
	return fields[19], nil
}

// ParseCgroup returns the control group path of a /proc/<pid>/cgroup dump: the
// unified hierarchy when there is one, the systemd named hierarchy otherwise.
func ParseCgroup(dump string) string {
	named := ""
	for _, line := range strings.Split(dump, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch parts[1] {
		case "":
			return parts[2]
		case "name=systemd":
			named = parts[2]
		}
	}
	return named
}
