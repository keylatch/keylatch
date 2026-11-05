package brokerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/control"
)

// Options configures Run.
type Options struct {
	Version   string
	StateRoot string
	Socket    string
	// Root loads the device root. Nil reads the systemd credential; the macOS and
	// Windows brokers supply the keychain and CNG loaders.
	Root func() ([]byte, error)
	// Listen opens the client endpoint. Nil adopts the socket systemd passed or
	// binds Socket; the Windows broker supplies its named pipe.
	Listen func() (Listener, error)
	// Helpers and HelperAdmit connect per-user presence helpers (see Config).
	Helpers     *HelperHub
	HelperAdmit func(ctx context.Context, peer control.Peer) error
	// Identify pins each peer. Nil uses the platform default.
	Identify func(control.Conn) (*Identity, error)
	// Allow overrides which users may use the broker.
	Allow func(uid uint32) bool
	// Binary is the keylatch executable the daemon runs for served verbs.
	Binary string
	// Env reads the environment (os.Getenv in production).
	Env func(string) string
	// PID is this process's id, matched against LISTEN_PID.
	PID int
	// Harden makes the process undumpable; it must succeed.
	Harden func() error
	// Unsetenv removes a variable from the process environment (os.Unsetenv in
	// production), so the verbs the daemon runs do not inherit the location of
	// the device root credential or the socket activation variables.
	Unsetenv func(string) error
	// RequireLock makes failing to lock key pages fatal.
	RequireLock bool
	// Presence overrides the presence method (polkit when installed).
	Presence PresenceMethod
	Out      io.Writer
}

// Run starts the broker and serves until ctx is done. It refuses to start
// without a device root, an audit log or a hardened process: a daemon that
// cannot protect its keys must not hold them.
func Run(ctx context.Context, o Options) error {
	if o.Harden != nil {
		if err := o.Harden(); err != nil {
			return fmt.Errorf("keylatchd: the process cannot be hardened: %w", err)
		}
	}
	if o.StateRoot == "" {
		o.StateRoot = DefaultStateRoot
	}
	if o.Socket == "" {
		o.Socket = DefaultSocket
	}
	if err := o.applyPlatform(); err != nil {
		return fmt.Errorf("keylatchd: %w", err)
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	loadRoot := o.Root
	if loadRoot == nil {
		loadRoot = func() ([]byte, error) { return keys.LoadRoot(o.Env("CREDENTIALS_DIRECTORY")) }
	}
	root, err := loadRoot()
	if err != nil {
		return fmt.Errorf("keylatchd: %w (run 'sudo keylatch broker install')", err)
	}
	h, err := keys.Open(filepath.Join(o.StateRoot, "keys"), root, o.RequireLock)
	clear(root)
	scrub := func(names ...string) {
		if o.Unsetenv == nil {
			return
		}
		for _, n := range names {
			_ = o.Unsetenv(n)
		}
	}
	scrub("CREDENTIALS_DIRECTORY")
	if err != nil {
		return fmt.Errorf("keylatchd: %w", err)
	}
	defer h.Close()

	logger, err := OpenAudit(filepath.Join(o.StateRoot, "audit"), h)
	if err != nil {
		return fmt.Errorf("keylatchd: the audit log cannot be opened, and Keylatch does not serve without an audit trail: %w", err)
	}
	defer func() { _ = logger.Close() }()
	if err := logger.Anchor(); err != nil {
		fmt.Fprintf(o.Out, "keylatchd: audit anchor not written to the OS log: %v\n", err)
	}

	presence := o.Presence
	if presence == nil {
		if p := NewPolkit(); p != nil {
			presence = p
		}
	}
	srv, err := New(Config{
		Version:     o.Version,
		StateRoot:   o.StateRoot,
		Binary:      o.Binary,
		Keys:        h,
		Audit:       audit.AsEmitter(logger),
		AuditHead:   logger.Head,
		Presence:    presence,
		Identify:    o.Identify,
		Allow:       o.Allow,
		Helpers:     o.Helpers,
		HelperAdmit: o.HelperAdmit,
		Gateway:     Gateway(logger),
	})
	if err != nil {
		return err
	}
	if err := srv.ResumeRotation(); err != nil {
		return fmt.Errorf("keylatchd: finish the interrupted key rotation: %w", err)
	}
	open := o.Listen
	if open == nil {
		open = func() (Listener, error) {
			ul, err := Listen(o.Socket, o.Env, o.PID)
			if err != nil {
				return nil, err
			}
			return UnixListener(ul), nil
		}
	}
	ln, err := open()
	scrub("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	if presence == nil {
		fmt.Fprintln(o.Out, "keylatchd: no presence method is available ("+presenceHint+"); privileged requests will be refused")
	}
	fmt.Fprintf(o.Out, "keylatchd: broker serving on %s\n", o.Socket)
	if err := srv.Serve(ctx, ln); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
