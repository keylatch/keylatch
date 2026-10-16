// Package adapter holds the sessions of tier D4. A session names one database
// the connection's template binds, issues the token the child uses as its
// password, and serves the child's connections through a protocol adapter that
// authenticates upstream with the stored credential.
package adapter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	b32 "encoding/base32"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/adapter/postgres"
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/registry"
)

const (
	defaultTTL = 15 * time.Minute
	maxTTL     = 8 * time.Hour
	// TokenPrefix marks a session token so a secret scanner and a person can
	// tell it from a database password.
	TokenPrefix = "klph_"
)

var (
	// ErrNotAdapter means the template declares no adapter this build serves.
	ErrNotAdapter = errors.New("adapter: the connection declares no supported protocol adapter")
	// ErrTarget means the requested database is not one the template binds.
	ErrTarget = errors.New("adapter: the target is outside the connection's adapter hosts")
)

// Config configures a Manager.
type Config struct {
	// Resolver reads the stored credential when a connection needs it.
	Resolver placeholder.Resolver
	// Audit receives one event per adapter connection. Sessions are refused
	// without it.
	Audit audit.Emitter
	// TTL bounds a session; zero selects fifteen minutes.
	TTL time.Duration
	// Upstream controls how databases are reached. The zero value dials with
	// the address guards the placeholder proxy uses.
	Upstream placeholder.Upstream
	// TLS and PlainUpstream configure the database connection; see postgres.Config.
	TLS           *tls.Config
	PlainUpstream bool
}

// OpenRequest describes a session to open.
type OpenRequest struct {
	Template registry.ConnectionTemplate
	// Target is the database, host:port; it must match the template's adapter hosts.
	Target string
	// User is the database role the adapter authenticates as.
	User string
	// Database is used when the client names none.
	Database string
}

// Manager opens and tracks sessions.
type Manager struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager returns a Manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("adapter: no credential resolver is configured")
	}
	if cfg.Audit == nil {
		return nil, errors.New("adapter: no audit log is configured")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	cfg.TTL = min(cfg.TTL, maxTTL)
	return &Manager{cfg: cfg, sessions: map[string]*Session{}}, nil
}

// Session is one child's database access.
type Session struct {
	id         string
	connection string
	kind       registry.AdapterKind
	token      string
	target     string
	user       string
	database   string
	pg         *postgres.Server
	cfg        Config

	ctx    context.Context
	cancel context.CancelFunc
	timer  *time.Timer
	onEnd  func(*Session)

	mu     sync.Mutex
	closed bool
	conns  int
}

// Open creates a session for the template's postgres adapter.
func (m *Manager) Open(req OpenRequest) (*Session, error) {
	ad := req.Template.Adapter
	if ad.Kind != registry.AdapterPostgres {
		return nil, ErrNotAdapter
	}
	target := strings.ToLower(strings.TrimSpace(req.Target))
	if target == "" {
		return nil, fmt.Errorf("%w: name the database as host:port", ErrTarget)
	}
	if h, p, err := net.SplitHostPort(target); err != nil || h == "" || p == "" {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "5432")
	}
	if !matchesAny(ad.Hosts, target) {
		return nil, fmt.Errorf("%w (%s)", ErrTarget, strings.Join(ad.Hosts, ", "))
	}
	user := req.User
	if user == "" {
		user = "postgres"
	}
	id, err := randomString(16)
	if err != nil {
		return nil, err
	}
	tokenBody, err := randomString(20)
	if err != nil {
		return nil, err
	}

	s := &Session{
		id: id, connection: req.Template.Provider, kind: ad.Kind, token: TokenPrefix + tokenBody,
		target: target, user: user, database: req.Database, cfg: m.cfg, onEnd: m.forget,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	field := ad.Field
	srv, err := postgres.New(postgres.Config{
		Token: s.token, Target: target, User: user, Database: req.Database,
		Password: func(ctx context.Context) ([]byte, error) {
			return m.cfg.Resolver.Resolve(ctx, s.connection, field)
		},
		TLS: m.cfg.TLS, PlainUpstream: m.cfg.PlainUpstream,
		Dial:   m.cfg.Upstream.DialContext,
		Report: s.report,
	})
	if err != nil {
		s.cancel()
		return nil, err
	}
	s.pg = srv
	if err := s.emit("opened"); err != nil {
		s.cancel()
		return nil, fmt.Errorf("adapter: audit log: %w", err)
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	s.mu.Lock()
	s.timer = time.AfterFunc(m.cfg.TTL, func() { s.Close("expired") })
	s.mu.Unlock()
	return s, nil
}

// Get returns an open session.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *Manager) forget(s *Session) {
	m.mu.Lock()
	delete(m.sessions, s.id)
	m.mu.Unlock()
}

// Close ends every open session.
func (m *Manager) Close() {
	m.mu.Lock()
	open := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		open = append(open, s)
	}
	m.mu.Unlock()
	for _, s := range open {
		s.Close("daemon stopping")
	}
}

// ID names the session on the control socket.
func (s *Session) ID() string { return s.id }

// Connection is the connection the session serves.
func (s *Session) Connection() string { return s.connection }

// Token is the password the child presents. It is worth nothing elsewhere.
func (s *Session) Token() string { return s.token }

// User is the database role the adapter authenticates as; it is not a secret.
func (s *Session) User() string { return s.user }

// Target is the database, host:port.
func (s *Session) Target() string { return s.target }

// Kind is the adapter protocol.
func (s *Session) Kind() registry.AdapterKind { return s.kind }

// Serve handles one client connection until it ends or the session closes.
func (s *Session) Serve(conn net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.conns++
	s.mu.Unlock()
	s.pg.Serve(s.ctx, conn)
}

// Close revokes the session: its token stops working and its connections end.
func (s *Session) Close(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	timer, conns := s.timer, s.conns
	s.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	s.cancel()
	if s.onEnd != nil {
		s.onEnd(s)
	}
	_ = s.emitExtra(reason, map[string]any{"connections": conns})
}

func (s *Session) report(reason string) { _ = s.emit(reason) }

func (s *Session) emit(reason string) error { return s.emitExtra(reason, nil) }

func (s *Session) emitExtra(reason string, extra map[string]any) error {
	ev := audit.Event{Action: audit.ActionAdapterConnection, Outcome: audit.OutcomeOK, Timestamp: time.Now().UTC(), Extra: map[string]any{
		"provider": s.connection, "adapter": string(s.kind), "host": s.target, "reason": reason, "session_id_hmac": s.id,
	}}
	for k, v := range extra {
		ev.Extra[k] = v
	}
	if reason == postgres.ReasonBadToken || reason == postgres.ReasonRefused || reason == postgres.ReasonUpstreamFailed {
		ev.Outcome = audit.OutcomeDenied
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.cfg.Audit.Emit(ctx, ev)
}

func matchesAny(patterns []string, authority string) bool {
	for _, p := range patterns {
		if registry.MatchAuthority(p, authority) {
			return true
		}
	}
	return false
}

func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("adapter: random source: %w", err)
	}
	return strings.ToLower(b32.StdEncoding.WithPadding(b32.NoPadding).EncodeToString(raw)), nil
}
