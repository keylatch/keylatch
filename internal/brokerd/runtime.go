package brokerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/paths"
)

// OpenAudit opens the daemon's audit log under dir. The chain seed and the
// sealing key come from the key hierarchy, so the log's integrity does not
// depend on a file the clients can read. The head is anchored to the OS log.
func OpenAudit(dir string, h *keys.Hierarchy) (*audit.Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("brokerd: %w", err)
	}
	seed, seal := h.AuditKeys()
	l, err := audit.Open(filepath.Join(dir, "audit.log"), seed, seal)
	if err != nil {
		return nil, fmt.Errorf("brokerd: %w", err)
	}
	l.SetAnchorSink(audit.OSLogAnchor)
	return l, nil
}

// Gateway returns the function that starts a partition's gateway inside the
// daemon: a loopback listener of the daemon's own user, serving secrets from
// the partition's store and authenticating tokens with the daemon's key. The
// address is private to the daemon; clients reach it only through the socket.
func Gateway(h *keys.Hierarchy, logger *audit.Logger) func(context.Context, GatewayPartition) (string, error) {
	return func(ctx context.Context, p GatewayPartition) (string, error) {
		key, err := h.TokenKey()
		if err != nil {
			return "", err
		}
		addr, err := freeLoopback()
		if err != nil {
			return "", err
		}
		srv, err := gateway.New(gateway.ServerOptions{
			Bind:           addr,
			SigningKey:     key,
			Mode:           gateway.ModeLocalProcess,
			Env:            p.Env,
			ApprovalsDir:   paths.ApprovalsDir(p.Env),
			TokenStorePath: paths.GatewayTokens(p.Env),
			AuditLogger:    logger,
			Vault:          p.Store,
			PolicyPath:     paths.Policy(p.Env),
		})
		if err != nil {
			return "", fmt.Errorf("gateway: %w", err)
		}
		go func() { _ = srv.Serve(ctx) }()
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				_ = c.Close()
				return addr, nil
			}
		}
		return "", errors.New("gateway did not start listening")
	}
}

func freeLoopback() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String(), nil
}

// firstListenFD is where systemd passes the first activated socket.
var firstListenFD uintptr = 3

// ListenFDs returns how many sockets systemd passed to this process, or 0 when
// the activation variables are absent or addressed to another process.
func ListenFDs(env func(string) string, pid int) int {
	if env("LISTEN_PID") != strconv.Itoa(pid) {
		return 0
	}
	n, err := strconv.Atoi(env("LISTEN_FDS"))
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// ListenFD adopts an already bound Unix socket.
func ListenFD(fd uintptr) (*net.UnixListener, error) {
	f := os.NewFile(fd, "listen")
	defer func() { _ = f.Close() }()
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("brokerd: adopt socket: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("brokerd: the activated socket is not a Unix socket")
	}
	return ul, nil
}

// Listen returns the broker socket: the one systemd activated, or a new one at
// path. The socket is world-connectable on purpose; the daemon identifies and
// admits each peer itself.
func Listen(path string, env func(string) string, pid int) (*net.UnixListener, error) {
	if ListenFDs(env, pid) > 0 {
		return ListenFD(firstListenFD)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: the socket directory must be traversable by users
		return nil, fmt.Errorf("brokerd: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("brokerd: a daemon is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("brokerd: remove stale socket: %w", err)
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("brokerd: listen: %w", err)
	}
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // G302: see above
		_ = ln.Close()
		return nil, fmt.Errorf("brokerd: %w", err)
	}
	return ln, nil
}
