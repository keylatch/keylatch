package brokerd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/control"
)

const (
	// SessionTTL bounds how long a registered agent scope and its ticket count.
	SessionTTL = 24 * time.Hour
	// MaxSessionsPerUser bounds the scopes one user can register.
	MaxSessionsPerUser = 64
	scopePrefix        = "keylatch-agent-"
	scopeSuffix        = ".scope"
)

// ErrBadScope means a registration names a control group the caller may not claim.
var ErrBadScope = errors.New("brokerd: the control group is not a keylatch agent scope in the caller's own user slice")

type registeredScope struct {
	id      string
	uid     uint32
	cgroup  string
	expires time.Time
}

// Sessions is the table of agent scopes the launcher registered. A peer whose
// control group is inside a registered scope is an agent; registering a scope
// can only make processes more restricted, never less, so it needs no presence.
type Sessions struct {
	key []byte
	now func() time.Time

	mu     sync.Mutex
	scopes map[string]registeredScope
}

// NewSessions returns an empty table. key signs the tickets it issues.
func NewSessions(key []byte, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{key: key, now: now, scopes: map[string]registeredScope{}}
}

// Register records the transient scope keylatch-agent-<id>.scope for uid and
// returns the daemon-signed ticket the harness carries. The scope must live in
// the caller's own user slice, so a user can only claim their own processes.
func (s *Sessions) Register(uid uint32, id, cgroup string) (string, error) {
	if !strings.HasSuffix(cgroup, "/"+scopePrefix+id+scopeSuffix) ||
		!strings.Contains(cgroup, "/user-"+uidString(uid)+".slice/") ||
		strings.Contains(cgroup, "..") {
		return "", ErrBadScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, sc := range s.scopes {
		switch {
		case s.now().After(sc.expires):
			delete(s.scopes, k)
		case sc.uid == uid:
			n++
		}
	}
	if _, exists := s.scopes[id]; !exists && n >= MaxSessionsPerUser {
		return "", fmt.Errorf("brokerd: %d agent sessions are already registered; end one first", MaxSessionsPerUser)
	}
	if old, ok := s.scopes[id]; ok && old.uid != uid {
		return "", ErrBadScope
	}
	exp := s.now().Add(SessionTTL)
	s.scopes[id] = registeredScope{id: id, uid: uid, cgroup: cgroup, expires: exp}
	return s.ticket(id, uid, exp), nil
}

// End forgets a scope the same user registered.
func (s *Sessions) End(uid uint32, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc, ok := s.scopes[id]; ok && sc.uid == uid {
		delete(s.scopes, id)
	}
}

// InAgentScope reports whether cgroup is a registered agent scope or below one.
func (s *Sessions) InAgentScope(cgroup string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scopes {
		if s.now().After(sc.expires) {
			continue
		}
		if cgroup == sc.cgroup || strings.HasPrefix(cgroup, sc.cgroup+"/") {
			return true
		}
	}
	return false
}

func (s *Sessions) ticket(id string, uid uint32, exp time.Time) string {
	body := id + "." + strconv.FormatInt(exp.Unix(), 10)
	return body + "." + s.mac(body, uid)
}

func (s *Sessions) mac(body string, uid uint32) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("keylatch/ticket/v1\x00" + uidString(uid) + "\x00" + body))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyTicket reports whether raw is an unexpired ticket this daemon issued to
// the peer's user and whose session is still registered.
func (s *Sessions) VerifyTicket(raw string, p control.Peer) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || s.now().Unix() > exp {
		return false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(s.mac(parts[0]+"."+parts[1], p.UID))) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.scopes[parts[0]]
	return ok && sc.uid == p.UID
}
