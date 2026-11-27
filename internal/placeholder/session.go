package placeholder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/registry"
)

// OpenRequest describes a session to open.
type OpenRequest struct {
	Template registry.ConnectionTemplate
	// UpstreamProxy is the proxy the caller's own environment names. The
	// session sends its upstream connections through it, so the host sandbox's
	// network policy stays authoritative for where traffic may go.
	UpstreamProxy string
	// Credential supplies the session's values instead of the Manager's
	// Resolver, for fields Keylatch produces at use time. The session closes it
	// when it ends.
	Credential Credential
}

// Credential supplies and later wipes the values of one session.
type Credential interface {
	// Value returns a fresh copy of the field's current value; the caller wipes it.
	Value(ctx context.Context, field string) ([]byte, error)
	Close()
}

// entry is one placeholder and what it is bound to.
type entry struct {
	field   string
	value   string
	maxUses int
	uses    int
}

// Session is one child's placeholders, CA and proxy.
type Session struct {
	id         string
	connection string
	binding    registry.Binding
	cfg        Config
	credential Credential
	ca         *sessionCA
	entries    []*entry
	finder     *finder
	transport  *http.Transport
	chain      *url.URL
	expires    time.Time
	timer      *time.Timer
	onClose    func(*Session)
	// decoys are the session's canary values. Seeing one in a request means
	// the child sent a credential it was never given.
	decoys  canary.Set
	decoyed *redactor.Matcher

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	redirects map[string]time.Time
	announced map[string]bool
	subs      int
	suspended bool
	closed    bool
}

// Manager opens and tracks sessions.
type Manager struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager returns a Manager. It fails when the configuration lacks a
// credential resolver or an audit log.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Resolver == nil {
		return nil, errNoResolver
	}
	if cfg.Audit == nil {
		return nil, errNoAudit
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	cfg.TTL = min(cfg.TTL, maxTTL)
	if cfg.MaxUses <= 0 {
		cfg.MaxUses = defaultMaxUses
	}
	return &Manager{cfg: cfg, sessions: map[string]*Session{}}, nil
}

// Open creates a session for the template's bindings.
func (m *Manager) Open(req OpenRequest) (*Session, error) {
	b, ok := req.Template.Binding()
	if !ok || len(b.Slots) == 0 {
		return nil, ErrNoBinding
	}
	chain, err := parseChain(req.UpstreamProxy)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	var entries []*entry
	var hosts []string
	for _, slot := range b.Slots {
		hosts = append(hosts, slot.Hosts...)
		if slices.ContainsFunc(entries, func(e *entry) bool { return e.field == slot.Field }) {
			continue
		}
		v, err := newValue(b.Shape)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &entry{field: slot.Field, value: v, maxUses: m.cfg.MaxUses})
	}
	ca, err := newSessionCA(id, hosts, m.cfg.TTL)
	if err != nil {
		return nil, err
	}
	values := make([]string, len(entries))
	for i, e := range entries {
		values[i] = e.value
	}

	decoys, err := canary.NewSet(req.Template.Provider)
	if err != nil {
		return nil, err
	}

	s := &Session{
		decoys:     decoys,
		decoyed:    redactor.NewMatcher(stringsToBytes(decoys.Values)...),
		id:         id,
		connection: req.Template.Provider,
		binding:    b,
		cfg:        m.cfg,
		credential: req.Credential,
		ca:         ca,
		entries:    entries,
		finder:     newFinder(values),
		transport:  m.cfg.Upstream.transport(chain),
		chain:      chain,
		expires:    time.Now().Add(m.cfg.TTL),
		conns:      map[net.Conn]struct{}{},
		redirects:  map[string]time.Time{},
		announced:  map[string]bool{},
		onClose:    m.forget,
	}
	if err := s.emit(audit.Event{Action: audit.ActionProxySession, Outcome: audit.OutcomeOK, Extra: map[string]any{
		"provider": s.connection, "reason": "opened", "hosts": len(hosts), "session_id_hmac": id,
	}}); err != nil {
		return nil, fmt.Errorf("placeholder: audit log: %w", err)
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
		s.Close("daemon_stopped")
	}
}

// Connection is the provider the session substitutes credentials for.
func (s *Session) Connection() string { return s.connection }

// ID identifies the session on the control socket.
func (s *Session) ID() string { return s.id }

// CAPEM is the session CA certificate a child must trust.
func (s *Session) CAPEM() []byte { return s.ca.pem }

// TTL is the time the session has left.
func (s *Session) TTL() time.Duration { return time.Until(s.expires) }

// Placeholders maps each bound secret field to the placeholder the child holds.
func (s *Session) Placeholders() map[string]string {
	out := make(map[string]string, len(s.entries))
	for _, e := range s.entries {
		out[e.field] = e.value
	}
	return out
}

// Canaries maps the environment variable that holds the session's decoy to
// its value. The child gets it next to its placeholders; the proxy suspends the
// session when the value, in any common encoding, appears in a request.
func (s *Session) Canaries() map[string]string { return s.decoys.Env }

// canaryWindow is the longest span a decoy can take once encoded, so a scan
// that keeps this many trailing bytes sees one split across two reads.
func (s *Session) canaryWindow() int {
	longest := 0
	for _, v := range s.decoys.Values {
		longest = max(longest, len(v))
	}
	return longest * 4
}

func stringsToBytes(in []string) [][]byte {
	out := make([][]byte, len(in))
	for i, v := range in {
		out[i] = []byte(v)
	}
	return out
}

// Suspended reports whether a misuse suspended the session.
func (s *Session) Suspended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suspended
}

// Close revokes the session: its placeholders stop working, its connections
// close and its CA key is dropped.
func (s *Session) Close(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	subs := s.subs
	conns := s.conns
	s.conns = map[net.Conn]struct{}{}
	timer := s.timer
	s.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	for c := range conns {
		_ = c.Close()
	}
	s.transport.CloseIdleConnections()
	s.ca.wipe()
	if s.credential != nil {
		s.credential.Close()
	}
	if s.onClose != nil {
		s.onClose(s)
	}
	_ = s.emit(audit.Event{Action: audit.ActionProxySession, Outcome: audit.OutcomeOK, Extra: map[string]any{
		"provider": s.connection, "reason": reason, "substitutions": subs, "session_id_hmac": s.id,
	}})
}

func (s *Session) emit(ev audit.Event) error {
	ev.Timestamp = time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.cfg.Audit.Emit(ctx, ev)
}

func (s *Session) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.suspended {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Session) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

var (
	errExpired   = errors.New("placeholder expired")
	errExhausted = errors.New("placeholder use limit reached")
)

// consume counts one request against each placeholder it substitutes.
func (s *Session) consume(es []*entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().After(s.expires) {
		return errExpired
	}
	for _, e := range es {
		if e.maxUses > 0 && e.uses >= e.maxUses {
			return errExhausted
		}
	}
	for _, e := range es {
		e.uses++
	}
	s.subs++
	return nil
}
