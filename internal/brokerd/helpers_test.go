//go:build unix

package brokerd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
)

// recorder collects audit events.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
	fail   error
}

func (r *recorder) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) count(a audit.Action) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Action == a {
			n++
		}
	}
	return n
}

func (r *recorder) last(a audit.Action) (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Action == a {
			return r.events[i], true
		}
	}
	return audit.Event{}, false
}

// fakePresence approves or refuses every request and records the subjects.
type fakePresence struct {
	mu       sync.Mutex
	err      error
	subjects []Subject
	actions  []string
}

func (*fakePresence) Name() string { return "fake" }

func (f *fakePresence) Verify(_ context.Context, s Subject, action, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjects = append(f.subjects, s)
	f.actions = append(f.actions, action)
	return f.err
}

type okPin struct{ err error }

func (p okPin) verify(*Identity) error { return p.err }
func (okPin) close()                   {}

func testKeys(t *testing.T) *keys.Hierarchy {
	t.Helper()
	h, err := keys.Open(t.TempDir(), bytes.Repeat([]byte{9}, 48), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

type harness struct {
	srv   *Server
	rec   *recorder
	pres  *fakePresence
	state string
	now   *time.Time
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{rec: &recorder{}, pres: &fakePresence{}, state: t.TempDir()}
	now := time.Unix(1_800_000_000, 0)
	h.now = &now
	cfg := Config{
		Version:   "test",
		StateRoot: h.state,
		Keys:      testKeys(t),
		Audit:     h.rec,
		Presence:  h.pres,
		AuditHead: func() audit.Head { return audit.Head{Seq: 7, Hash: "ab12"} },
		Now:       func() time.Time { return *h.now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h
}

// peerAs returns the peer a request from uid with the given cgroup arrives as.
func peerAs(uid uint32, cgroup string) control.Peer {
	return control.Peer{UID: uid, PID: 4242, Start: "9999", Cgroup: cgroup}
}

var host = callerkind.Result{Kind: callerkind.Host}

// send runs a request through the partition of uid as a host caller.
func (h *harness) send(t *testing.T, uid uint32, req brokerapi.Request) brokerapi.Response {
	t.Helper()
	return h.sendAs(t, peerAs(uid, ""), host, req)
}

func (h *harness) sendAs(t *testing.T, peer control.Peer, res callerkind.Result, req brokerapi.Request) brokerapi.Response {
	t.Helper()
	p, err := h.srv.partition(context.Background(), peer.UID)
	if err != nil {
		t.Fatal(err)
	}
	return (&admin{s: h.srv, p: p}).dispatch(context.Background(), peer, res, req)
}

// proven obtains a proof for req through presence.begin and returns req with it.
func (h *harness) proven(t *testing.T, uid uint32, req brokerapi.Request) brokerapi.Request {
	t.Helper()
	resp := h.send(t, uid, brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &req})
	if !resp.OK || resp.Proof == nil {
		t.Fatalf("presence.begin = %+v", resp)
	}
	req.Proof = resp.Proof.ID
	return req
}

// pair returns the two ends of a connected Unix socket. Socket pairs need no
// bind, so they work where a sandbox forbids listening.
func pair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket pairs are not permitted here: %v", err)
	}
	ends := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		ends[i] = c.(*net.UnixConn)
		t.Cleanup(func() { _ = c.Close() })
	}
	return ends[0], ends[1]
}

// chanListener hands out the server ends of socket pairs.
type chanListener struct {
	ch   chan *net.UnixConn
	once sync.Once
}

func (l *chanListener) AcceptUnix() (*net.UnixConn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.ch) })
	return nil
}

// serve runs the daemon on a fake listener and returns a function that sends
// one frame over a fresh connection and decodes the first reply frame.
func (h *harness) serve(t *testing.T) (call func(frame, out any), stop func()) {
	t.Helper()
	ln := &chanListener{ch: make(chan *net.UnixConn)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Serve(ctx, ln) }()
	stop = func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	}
	t.Cleanup(func() { _ = ln.Close() })
	call = func(frame, out any) {
		t.Helper()
		server, client := pair(t)
		ln.ch <- server
		b, _ := json.Marshal(frame)
		if _, err := client.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(client).ReadBytes('\n')
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if err := json.Unmarshal(line, out); err != nil {
			t.Fatalf("decode reply %q: %v", line, err)
		}
	}
	return call, stop
}
