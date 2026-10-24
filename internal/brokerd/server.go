package brokerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/brokerstore"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/runner"
)

// Default bounds on which accounts may use the broker.
const (
	DefaultMinUID = 1000
	DefaultMaxUID = 60000
)

// Config configures a Server.
type Config struct {
	Version string
	// StateRoot holds one partition per user under users/<uid>/ (default
	// /var/lib/keylatch).
	StateRoot string
	// Binary is the keylatch executable the daemon runs for served verbs.
	Binary string
	Keys   *keys.Hierarchy
	// Audit receives every decision. Nil refuses to serve: the daemon does not
	// act without an audit trail.
	Audit audit.Emitter
	// AuditHead reports the audit chain head.
	AuditHead func() audit.Head
	// Presence verifies human presence; nil means privileged requests are refused.
	Presence PresenceMethod
	// Helpers holds the presence helpers connected through presence.helper; nil
	// refuses that operation.
	Helpers *HelperHub
	// HelperAdmit decides whether a peer may register as a presence helper (the
	// macOS broker checks its code identity).
	HelperAdmit func(ctx context.Context, peer control.Peer) error
	// Identify pins the peer; nil uses the platform's kernel facility (pidfd and
	// SO_PEERCRED, LOCAL_PEERTOKEN, or the named pipe client token).
	Identify func(control.Conn) (*Identity, error)
	// Allow decides which users may use the broker; nil admits UIDs from
	// DefaultMinUID up to DefaultMaxUID.
	Allow func(uid uint32) bool
	// Gateway starts the gateway listener of a partition and returns its
	// loopback address. Nil leaves the gateway tier unavailable.
	Gateway func(ctx context.Context, p GatewayPartition) (addr string, err error)
	Now     func() time.Time
	// Sync tunes the deploy-secret sync operations.
	Sync SyncConfig
	// Units inspects service units for enrollment and release; nil asks systemctl.
	Units UnitInspector
	// CallAction performs a provider action for a machine; nil uses
	// runner.ExecuteAction.
	CallAction func(ctx context.Context, baseURL, provider, action string, params map[string]string, creds string) (*runner.ActionResult, error)
	// MachineListen binds the machine listener; nil uses net.Listen.
	MachineListen func(network, addr string) (net.Listener, error)
}

// GatewayPartition is what the gateway needs to serve one partition.
type GatewayPartition struct {
	UID       uint32
	ConfigDir string
	Store     *brokerstore.Store
	Env       func(string) string
	// TokenKey returns the key this partition's session tokens are authenticated with.
	TokenKey func() ([]byte, error)
}

// Server is the system broker.
type Server struct {
	cfg      Config
	proofs   *Proofs
	presence *Presence
	sessions *Sessions
	callers  *callerkind.Classifier

	mu    sync.Mutex
	parts map[uint32]*partition

	denials denyLimiter

	svcOnce sync.Once
	svc     *serviceStore

	machOnce sync.Once
	mach     *machineStore
	machines machineManager
}

type partition struct {
	uid    uint32
	dir    string
	env    func(string) string
	store  *brokerstore.Store
	policy *PolicyStore
	ctl    *control.Server

	syncOnce sync.Once
	sync     *syncState
	// syncStore stands in for store in the sync operations; tests use it to
	// count reads.
	syncStore secretStore
}

func (p *partition) configDir() string { return filepath.Join(p.dir, "config") }

// New returns a Server. It refuses a configuration that could serve without an
// audit log, keys or a state directory.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Keys == nil:
		return nil, errors.New("brokerd: a key hierarchy is required")
	case cfg.Audit == nil:
		return nil, errors.New("brokerd: an audit log is required; the daemon does not act without one")
	case cfg.StateRoot == "":
		return nil, errors.New("brokerd: a state directory is required")
	}
	if cfg.Identify == nil {
		cfg.Identify = Identify
	}
	if cfg.Allow == nil {
		cfg.Allow = func(uid uint32) bool { return uid >= DefaultMinUID && uid <= DefaultMaxUID }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ticketKey, err := cfg.Keys.TokenKey()
	if err != nil {
		return nil, fmt.Errorf("brokerd: %w", err)
	}
	proofs := NewProofs(cfg.Now)
	sessions := NewSessions(ticketKey, cfg.Now)
	s := &Server{
		cfg:      cfg,
		proofs:   proofs,
		sessions: sessions,
		presence: &Presence{Method: cfg.Presence, Proofs: proofs, Audit: cfg.Audit},
		callers:  &callerkind.Classifier{NoHuman: true, AgentScope: sessions.InAgentScope},
		parts:    map[uint32]*partition{},
	}
	if cfg.Presence == nil {
		s.presence.Method = nil
	}
	return s, nil
}

// Sessions exposes the agent scope table.
func (s *Server) Sessions() *Sessions { return s.sessions }

// Listener accepts client connections: a Unix socket listener (see
// UnixListener) or the Windows named pipe listener.
type Listener interface {
	Accept() (control.Conn, error)
	Close() error
}

type unixListener struct{ *net.UnixListener }

func (l unixListener) Accept() (control.Conn, error) { return l.AcceptUnix() }

// UnixListener serves a *net.UnixListener as a Listener.
func UnixListener(l *net.UnixListener) Listener { return unixListener{l} }

// Serve accepts connections until ctx is done.
func (s *Server) Serve(ctx context.Context, ln Listener) error {
	s.StartMachineListener(ctx)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = conn.Close() }()
			s.handle(ctx, conn)
		}()
	}
}

func refuse(conn net.Conn, code string, exit int, msg string) {
	b, _ := json.Marshal(control.Response{Code: code, ExitCode: exit, Error: msg})
	_, _ = conn.Write(append(b, '\n'))
}

func (s *Server) handle(ctx context.Context, conn control.Conn) {
	id, err := s.cfg.Identify(conn)
	if err != nil {
		refuse(conn, control.CodeRefused, exitcode.SecurityBlock, "the daemon could not identify the calling process: "+err.Error())
		return
	}
	defer id.Close()
	if !s.cfg.Allow(id.UID) {
		s.serveServiceOnly(ctx, conn, id)
		return
	}
	p, err := s.partition(ctx, id.UID)
	if err != nil {
		slog.Error("partition unavailable", "uid", id.UID, "error", err)
		refuse(conn, control.CodeUnavailable, exitcode.OperationFailed, "the user's partition is unavailable")
		return
	}
	p.ctl.ServeConn(ctx, conn, id.Peer())
}

// PartitionDir returns the directory holding uid's state.
func (s *Server) PartitionDir(uid uint32) string {
	return filepath.Join(s.cfg.StateRoot, "users", uidString(uid))
}

type partEnv struct {
	mu   sync.RWMutex
	vals map[string]string
}

func (e *partEnv) lookup(k string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.vals[k]
}

func (e *partEnv) set(k, v string) {
	e.mu.Lock()
	e.vals[k] = v
	e.mu.Unlock()
}

// partition returns uid's partition, creating its directories and its control
// server on first use. A user's server sees only that user's directory.
func (s *Server) partition(ctx context.Context, uid uint32) (*partition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.parts[uid]; ok {
		return p, nil
	}
	dir := s.PartitionDir(uid)
	cfgDir, storeDir := filepath.Join(dir, "config"), filepath.Join(dir, "store")
	for _, d := range []string{cfgDir, storeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	store, err := brokerstore.Open(storeDir, uidString(uid), s.cfg.Keys)
	if err != nil {
		return nil, err
	}
	env := &partEnv{vals: map[string]string{"KEYLATCH_CONFIG_DIR": cfgDir}}
	childEnv := []string{"KEYLATCH_CONFIG_DIR=" + cfgDir}
	tokenKey := func() ([]byte, error) { return s.cfg.Keys.TokenKeyFor(uidString(uid)) }
	if s.cfg.Gateway != nil {
		addr, err := s.cfg.Gateway(ctx, GatewayPartition{UID: uid, ConfigDir: cfgDir, Store: store, Env: env.lookup, TokenKey: tokenKey})
		if err != nil {
			slog.Warn("gateway unavailable for partition", "uid", uid, "error", err)
		} else {
			env.set("KEYLATCH_GATEWAY_ADDR", addr)
			childEnv = append(childEnv, "KEYLATCH_GATEWAY_ADDR="+addr)
		}
	}
	pol := &PolicyStore{Dir: cfgDir, Keys: s.cfg.Keys, Audit: s.cfg.Audit, Now: s.cfg.Now}
	p := &partition{uid: uid, dir: dir, env: env.lookup, store: store, policy: pol}
	keyService, keyAdmin, err := s.keyService(p)
	if err != nil {
		return nil, err
	}
	p.ctl = control.NewServer(control.Config{
		Env:             env.lookup,
		Binary:          s.cfg.Binary,
		Audit:           s.cfg.Audit,
		Callers:         s.callers,
		SigningKey:      tokenKey,
		ChildEnv:        childEnv,
		ChildStore:      store,
		Decide:          enforce.New(env.lookup).Decide,
		Gate:            pol.Gate,
		Ticket:          s.sessions.VerifyTicket,
		Extension:       &admin{s: s, p: p},
		Keys:            keyService,
		KeyAdmin:        keyAdmin,
		KeyPeerPresence: s.keyPresence(uid),
	})
	s.parts[uid] = p
	return p, nil
}

// partitions lists the users that have a partition on disk.
func (s *Server) partitions() ([]uint32, error) {
	entries, err := os.ReadDir(filepath.Join(s.cfg.StateRoot, "users"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, e := range entries {
		var uid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &uid); err == nil && e.IsDir() {
			out = append(out, uid)
		}
	}
	return out, nil
}

// rewrapAll moves every partition's data keys from the old master key to the
// staged one.
func (s *Server) rewrapAll(oldKEK, newKEK keys.KEKFunc, newKID string) error {
	uids, err := s.partitions()
	if err != nil {
		return err
	}
	for _, uid := range uids {
		st, err := brokerstore.Open(filepath.Join(s.PartitionDir(uid), "store"), uidString(uid), s.cfg.Keys)
		if err != nil {
			return err
		}
		name := uidString(uid)
		if _, err := st.Rewrap(oldKEK(name), newKEK(name), newKID); err != nil {
			return fmt.Errorf("partition %d: %w", uid, err)
		}
	}
	return nil
}

// ResumeRotation finishes a master key rotation that was staged but not
// committed before the daemon stopped.
func (s *Server) ResumeRotation() error {
	return s.cfg.Keys.Resume(s.rewrapAll)
}
