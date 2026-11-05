// Package socketrelay forwards bytes between a caller's stdio and the daemon's
// control socket. It is the body of keylatch-relay, a binary meant to be
// installed root- or package-owned and listed as a harness's excluded command
// where the harness sandbox cannot reach a Unix socket.
//
// The relay holds no key material, never starts a process, never reads its
// arguments and has no flag that changes where it connects. What the caller
// sends is the daemon's to decide.
package socketrelay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DefaultSocket is the control socket location fixed at build time with
// -ldflags "-X github.com/keylatch/keylatch/internal/socketrelay.DefaultSocket=<path>".
// Empty selects the per-user default.
var DefaultSocket string

// SocketEnv names the optional override of the socket path. The override is
// honored only when it is a socket owned by the relay's own user inside a
// directory only that user can write.
const SocketEnv = "KEYLATCH_SOCKET"

// Lookup resolves an environment variable name to its value.
type Lookup func(string) string

// SocketPath returns the path the relay connects to.
func SocketPath(env Lookup) string {
	if v := env(SocketEnv); v != "" {
		return v
	}
	if DefaultSocket != "" {
		return DefaultSocket
	}
	if xdg := env("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "keylatch", "keylatchd.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("keylatch-%d", os.Getuid()), "keylatchd.sock")
}

// Run connects to the daemon and copies in to it and its replies to out until
// the daemon closes the connection. Arguments never reach this function.
func Run(env Lookup, in io.Reader, out io.Writer) error {
	uid := uint32(os.Getuid()) //nolint:gosec // G115: uid is non-negative
	path := SocketPath(env)
	if err := checkOwned(path, uid); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no daemon on the control socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	uc := conn.(*net.UnixConn)
	peer, err := peerUID(uc)
	if err != nil || peer != uid {
		return errors.New("control socket: the listener is not this user's daemon")
	}

	go func() {
		_, _ = io.Copy(uc, in)
		_ = uc.CloseWrite()
	}()
	_, err = io.Copy(out, uc)
	return err
}
