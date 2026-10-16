//go:build unix

package brokerd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

const (
	agentID    = "agent-abc12345"
	agentScope = "/user.slice/user-1000.slice/user@1000.service/app.slice/keylatch-agent-" + agentID + ".scope"
)

func newSessions() (*Sessions, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	return NewSessions([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now }), &now
}

func classify(s *Server, p control.Peer, signals []string, ticket string) callerkind.Result {
	return s.callers.Peer(callerkind.Evidence{
		PID: p.PID, Cgroup: p.Cgroup, SharesNamespaces: true, Signals: signals,
		TicketValid: s.sessions.VerifyTicket(ticket, p),
	})
}

func TestLaunchedAgentClassified(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionRegister, Session: &brokerapi.SessionRequest{ID: agentID, Cgroup: agentScope}})
	if !resp.OK || resp.Session.Ticket == "" {
		t.Fatalf("register = %+v", resp)
	}

	// A process in the registered scope is an agent, with no env signals at all.
	inside := peerAs(1000, agentScope)
	if got := classify(h.srv, inside, nil, ""); got.Kind != callerkind.Agent || !strings.Contains(strings.Join(got.Reasons, ","), "agent-scope") {
		t.Fatalf("a process in the scope = %+v", got)
	}
	// So is one nested deeper in it (a child cgroup).
	if got := classify(h.srv, peerAs(1000, agentScope+"/sub"), nil, ""); got.Kind != callerkind.Agent {
		t.Fatalf("a process in a child cgroup = %+v", got)
	}
	// And a process that carries the daemon-signed ticket, wherever it runs.
	outside := peerAs(1000, "/user.slice/user-1000.slice/session-3.scope")
	if got := classify(h.srv, outside, nil, resp.Session.Ticket); got.Kind != callerkind.Agent {
		t.Fatalf("a ticketed process = %+v", got)
	}
	// The same ticket presented by another user is worthless.
	if got := classify(h.srv, peerAs(1001, outside.Cgroup), nil, resp.Session.Ticket); got.Kind != callerkind.Host {
		t.Fatalf("another user's ticket = %+v", got)
	}
}

func TestSessionTicketsAreBoundToTheLauncher(t *testing.T) {
	h := newHarness(t, nil)
	reg := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionRegister, Session: &brokerapi.SessionRequest{ID: agentID, Cgroup: agentScope}})
	if !reg.OK || reg.Session.PID != 4242 || reg.Session.Start != 9999 {
		t.Fatalf("register = %+v", reg)
	}
	// A client verifies its ticket with the daemon and learns the launcher it must descend from.
	ok := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: reg.Session.Ticket})
	if !ok.OK || ok.Session.PID != 4242 || ok.Session.Start != 9999 {
		t.Fatalf("verify = %+v", ok)
	}
	for name, resp := range map[string]brokerapi.Response{
		"another user": h.send(t, 1001, brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: reg.Session.Ticket}),
		"a forgery":    h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: reg.Session.Ticket + "0"}),
	} {
		if resp.OK || resp.Code != brokerapi.CodeRefused {
			t.Errorf("verify for %s = %+v", name, resp)
		}
	}
	h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionEnd, Session: &brokerapi.SessionRequest{ID: agentID}})
	if resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionVerify, Ticket: reg.Session.Ticket}); resp.OK {
		t.Fatalf("a ticket of an ended session verified: %+v", resp)
	}
	if resp := h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionRegister, Session: &brokerapi.SessionRequest{ID: agentID, Cgroup: "/system.slice/x.scope"}}); resp.OK || resp.Code != brokerapi.CodeRefused {
		t.Fatalf("a registration outside the user slice = %+v", resp)
	}
}

func TestEscapedProcessIsHostNotHuman(t *testing.T) {
	h := newHarness(t, nil)
	h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionRegister, Session: &brokerapi.SessionRequest{ID: agentID, Cgroup: agentScope}})

	// systemd-run --user --scope moves a process into a scope the launcher never registered.
	escaped := peerAs(1000, "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1234.scope")
	got := classify(h.srv, escaped, nil, "")
	if got.Kind != callerkind.Host {
		t.Fatalf("an escaped process = %+v, want host", got)
	}
	for _, p := range []control.Peer{escaped, peerAs(1000, ""), peerAs(1000, "/")} {
		if k := classify(h.srv, p, nil, "").Kind; k == callerkind.Human || k == callerkind.Service {
			t.Fatalf("a peer without presence was classified %s", k)
		}
	}
	// A look-alike scope name outside the registered path is not the scope.
	if got := classify(h.srv, peerAs(1000, agentScope+"x"), nil, ""); got.Kind != callerkind.Host {
		t.Fatalf("a path sharing the scope's prefix = %+v", got)
	}
	// Once the launcher ends the session, its processes are host again.
	h.send(t, 1000, brokerapi.Request{Op: brokerapi.OpSessionEnd, Session: &brokerapi.SessionRequest{ID: agentID}})
	if got := classify(h.srv, peerAs(1000, agentScope), nil, ""); got.Kind != callerkind.Host {
		t.Fatalf("a process of an ended session = %+v", got)
	}
	// Hiding every signal never reaches human: the daemon has no such class for peers.
	if got := classify(h.srv, peerAs(1000, ""), []string{llmcontext.SignalTicket}, ""); got.Kind != callerkind.Agent {
		t.Fatalf("a peer reporting a signal = %+v", got)
	}
}

func TestSessionRegistrationRules(t *testing.T) {
	s, now := newSessions()
	for name, cgroup := range map[string]string{
		"not an agent scope":   "/user.slice/user-1000.slice/app.slice/other.scope",
		"another user's slice": "/user.slice/user-1001.slice/user@1001.service/app.slice/keylatch-agent-" + agentID + ".scope",
		"no user slice":        "/system.slice/keylatch-agent-" + agentID + ".scope",
		"traversal":            "/user.slice/user-1000.slice/../keylatch-agent-" + agentID + ".scope",
		"another session's id": "/user.slice/user-1000.slice/keylatch-agent-agent-zzzzzzzz.scope",
		"empty":                "",
	} {
		if _, err := s.Register(1000, agentID, cgroup); !errors.Is(err, ErrBadScope) {
			t.Errorf("%s: Register = %v, want ErrBadScope", name, err)
		}
	}
	if _, err := s.Register(1000, agentID, agentScope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(1001, agentID, strings.ReplaceAll(agentScope, "1000", "1001")); !errors.Is(err, ErrBadScope) {
		t.Fatalf("taking over another user's session id = %v", err)
	}
	// End by another user does nothing.
	s.End(1001, agentID)
	if !s.InAgentScope(agentScope) {
		t.Fatal("another user ended the session")
	}
	// Scopes expire.
	*now = now.Add(SessionTTL + time.Second)
	if s.InAgentScope(agentScope) {
		t.Fatal("an expired scope still classifies")
	}
	if s.VerifyTicket("x.y.z", control.Peer{UID: 1000}) || s.VerifyTicket("a.b", control.Peer{}) || s.VerifyTicket("a.notanumber.c", control.Peer{}) {
		t.Fatal("malformed tickets must not verify")
	}
}

func TestSessionLimitsAndTicketForgery(t *testing.T) {
	s, _ := newSessions()
	var ticket string
	for i := 0; i < MaxSessionsPerUser; i++ {
		id := "agent-" + strings.Repeat("a", 4) + string(rune('a'+i/26)) + string(rune('a'+i%26)) + "000"
		scope := "/user.slice/user-1000.slice/keylatch-agent-" + id + ".scope"
		tk, err := s.Register(1000, id, scope)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		ticket = tk
	}
	if _, err := s.Register(1000, "agent-overflow", "/user.slice/user-1000.slice/keylatch-agent-agent-overflow.scope"); err == nil {
		t.Fatal("the per-user session cap must hold")
	}
	// Re-registering an existing session is not growth.
	if _, err := s.Register(1000, "agent-"+strings.Repeat("a", 4)+"aa000", "/user.slice/user-1000.slice/keylatch-agent-agent-"+strings.Repeat("a", 4)+"aa000.scope"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	// A ticket with a tampered expiry or id fails.
	parts := strings.Split(ticket, ".")
	parts[1] = "9999999999"
	if s.VerifyTicket(strings.Join(parts, "."), control.Peer{UID: 1000}) {
		t.Fatal("a ticket with an extended expiry verified")
	}
	if !s.VerifyTicket(ticket, control.Peer{UID: 1000}) {
		t.Fatal("a genuine ticket must verify")
	}
	s.End(1000, parts[0])
	if s.VerifyTicket(ticket, control.Peer{UID: 1000}) {
		t.Fatal("a ticket of an ended session verified")
	}
}
