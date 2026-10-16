package adapter

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/registry"
)

const dbPassword = "stored-database-password-0123456789"

type resolverFunc func(ctx context.Context, connection, field string) ([]byte, error)

func (f resolverFunc) Resolve(ctx context.Context, connection, field string) ([]byte, error) {
	return f(ctx, connection, field)
}

type events struct {
	mu   sync.Mutex
	list []audit.Event
}

func (e *events) Emit(_ context.Context, ev audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.list = append(e.list, ev)
	return nil
}

func (e *events) reasons() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.list {
		if ev.Action == audit.ActionAdapterConnection {
			out = append(out, ev.Extra["reason"].(string))
		}
	}
	return out
}

func supabase() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "supabase",
		Adapter: registry.Adapter{
			Kind: registry.AdapterPostgres, Field: "db_password",
			Hosts: []string{"*.supabase.co:5432", "*.pooler.supabase.com:6543"},
		},
	}
}

// trustDatabase answers any startup with AuthenticationOk and ReadyForQuery,
// reports the user it was given, then echoes.
func trustDatabase(t *testing.T, users chan<- string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		near, far := net.Pipe()
		go func() {
			defer func() { _ = far.Close() }()
			var head [8]byte
			if _, err := io.ReadFull(far, head[:]); err != nil {
				return
			}
			body := make([]byte, binary.BigEndian.Uint32(head[:4])-8)
			if _, err := io.ReadFull(far, body); err != nil {
				return
			}
			users <- string(body)
			_, _ = far.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'})
			_, _ = io.Copy(far, far)
		}()
		return near, nil
	}
}

func newManager(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) (*Manager, *events) {
	t.Helper()
	ev := &events{}
	m, err := NewManager(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]byte, error) { return []byte(dbPassword), nil }),
		Audit:    ev, Upstream: placeholder.Upstream{Dial: dial}, PlainUpstream: true,
	})
	require.NoError(t, err)
	t.Cleanup(m.Close)
	return m, ev
}

func startupPacket(user string) []byte {
	body := []byte("user\x00" + user + "\x00\x00")
	b := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(b, uint32(8+len(body)))
	binary.BigEndian.PutUint32(b[4:], 196608)
	return append(b, body...)
}

func TestOpenValidatesTemplateAndTarget(t *testing.T) {
	m, _ := newManager(t, nil)

	_, err := m.Open(OpenRequest{Template: registry.ConnectionTemplate{Provider: "stripe"}, Target: "db.example.supabase.co:5432"})
	assert.ErrorIs(t, err, ErrNotAdapter)

	for _, target := range []string{"", "evil.example.com:5432", "db.abc.supabase.co:6543", "169.254.169.254:5432"} {
		_, err := m.Open(OpenRequest{Template: supabase(), Target: target})
		assert.ErrorIs(t, err, ErrTarget, target)
	}

	s, err := m.Open(OpenRequest{Template: supabase(), Target: "DB.abc.supabase.co"})
	require.NoError(t, err)
	assert.Equal(t, "db.abc.supabase.co:5432", s.Target(), "the port defaults to 5432 and the name is lower-cased")
	assert.Equal(t, "postgres", s.User())
	assert.Equal(t, registry.AdapterPostgres, s.Kind())
	assert.Equal(t, "supabase", s.Connection())
	assert.True(t, strings.HasPrefix(s.Token(), TokenPrefix))
	got, ok := m.Get(s.ID())
	assert.True(t, ok)
	assert.Same(t, s, got)
}

func TestSessionServesWithTheTokenAndAuthenticatesAsTheRole(t *testing.T) {
	users := make(chan string, 4)
	m, ev := newManager(t, trustDatabase(t, users))
	s, err := m.Open(OpenRequest{Template: supabase(), Target: "db.abc.supabase.co:5432", User: "app_owner", Database: "prod"})
	require.NoError(t, err)

	near, far := net.Pipe()
	done := make(chan struct{})
	go func() { s.Serve(far); close(done) }()
	_, err = near.Write(startupPacket("klph"))
	require.NoError(t, err)
	buf := make([]byte, 9)
	_, err = io.ReadFull(near, buf)
	require.NoError(t, err)
	assert.Equal(t, byte('R'), buf[0])
	_, err = near.Write(append([]byte{'p', 0, 0, 0, byte(4 + len(s.Token()) + 1)}, append([]byte(s.Token()), 0)...))
	require.NoError(t, err)
	go func() { _, _ = io.Copy(io.Discard, near) }()

	select {
	case startup := <-users:
		assert.Contains(t, startup, "user\x00app_owner\x00")
		assert.Contains(t, startup, "database\x00prod\x00")
		assert.NotContains(t, startup, "klph")
	case <-time.After(5 * time.Second):
		t.Fatal("the database never saw a connection")
	}
	require.Eventually(t, func() bool { return len(ev.reasons()) >= 2 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"opened", "connected"}, ev.reasons()[:2])

	s.Close("run finished")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the session did not end its connection")
	}
	_ = near.Close()
	assert.Contains(t, ev.reasons(), "run finished")

	for _, e := range ev.list {
		for _, v := range e.Extra {
			assert.NotContains(t, strings.ToLower(toString(v)), strings.ToLower(s.Token()), "no event carries the token")
			assert.NotContains(t, toString(v), dbPassword)
		}
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestAClosedSessionServesNothingAndIsForgotten(t *testing.T) {
	m, ev := newManager(t, nil)
	s, err := m.Open(OpenRequest{Template: supabase(), Target: "db.abc.supabase.co:5432"})
	require.NoError(t, err)
	s.Close("revoked")
	s.Close("again")
	_, ok := m.Get(s.ID())
	assert.False(t, ok)

	near, far := net.Pipe()
	go s.Serve(far)
	_ = near.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = near.Read(make([]byte, 1))
	assert.Error(t, err, "the connection is closed without an answer")
	assert.Equal(t, 1, strings.Count(strings.Join(ev.reasons(), ","), "revoked"), "closing twice records once")
}

func TestSessionsExpire(t *testing.T) {
	ev := &events{}
	m, err := NewManager(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]byte, error) { return nil, nil }),
		Audit:    ev, TTL: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	s, err := m.Open(OpenRequest{Template: supabase(), Target: "db.abc.supabase.co:5432"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := m.Get(s.ID()); return !ok }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return slices.Contains(ev.reasons(), "expired") }, 5*time.Second, 5*time.Millisecond)
}

func TestManagerCloseEndsEverySession(t *testing.T) {
	m, _ := newManager(t, nil)
	a, err := m.Open(OpenRequest{Template: supabase(), Target: "db.a.supabase.co:5432"})
	require.NoError(t, err)
	b, err := m.Open(OpenRequest{Template: supabase(), Target: "db.b.supabase.co:5432"})
	require.NoError(t, err)
	m.Close()
	for _, s := range []*Session{a, b} {
		_, ok := m.Get(s.ID())
		assert.False(t, ok)
	}
}

func TestNewManagerNeedsAResolverAndAnAuditLog(t *testing.T) {
	_, err := NewManager(Config{Audit: &events{}})
	assert.Error(t, err)
	_, err = NewManager(Config{Resolver: resolverFunc(func(context.Context, string, string) ([]byte, error) { return nil, nil })})
	assert.Error(t, err)
	m, err := NewManager(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]byte, error) { return nil, nil }),
		Audit:    &events{}, TTL: 48 * time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, maxTTL, m.cfg.TTL)
}

type failingAudit struct{}

func (failingAudit) Emit(context.Context, audit.Event) error { return io.ErrClosedPipe }

func TestOpenFailsWhenTheAuditLogCannotRecord(t *testing.T) {
	m, err := NewManager(Config{
		Resolver: resolverFunc(func(context.Context, string, string) ([]byte, error) { return nil, nil }),
		Audit:    failingAudit{},
	})
	require.NoError(t, err)
	_, err = m.Open(OpenRequest{Template: supabase(), Target: "db.abc.supabase.co:5432"})
	assert.Error(t, err)
	assert.Empty(t, m.sessions)
}
