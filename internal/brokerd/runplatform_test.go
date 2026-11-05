package brokerd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/control"
)

type pipeListener struct {
	ch   chan control.Conn
	once sync.Once
}

func (l *pipeListener) Accept() (control.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.ch) })
	return nil
}

type approvingPresence struct{}

func (approvingPresence) Name() string { return "test" }
func (approvingPresence) Verify(context.Context, Subject, string, string) error {
	return nil
}

// Run on the listener, root loader and identity the platform supplies, with no
// systemd socket activation: the path the macOS and Windows services take.
func TestRunServesTheConfiguredListener(t *testing.T) {
	ln := &pipeListener{ch: make(chan control.Conn)}
	out := &bytes.Buffer{}
	o := Options{
		Version:   "test",
		StateRoot: t.TempDir(),
		Socket:    "platform-endpoint",
		Root:      func() ([]byte, error) { return bytes.Repeat([]byte{4}, 48), nil },
		Listen:    func() (Listener, error) { return ln, nil },
		Identify: func(control.Conn) (*Identity, error) {
			return &Identity{UID: 1000, PID: 1, Start: "1", pin: noPin{}}, nil
		},
		Presence:    approvingPresence{},
		Helpers:     NewHelperHub(),
		HelperAdmit: func(context.Context, control.Peer) error { return nil },
		Out:         out,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, o) }()

	server, client := connPair()
	select {
	case ln.ch <- server:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon never started listening")
	}
	b, _ := json.Marshal(brokerapi.Request{Op: brokerapi.OpStatus})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var resp brokerapi.Response
	if err := json.Unmarshal(line, &resp); err != nil || !resp.OK || resp.Status == nil || resp.Status.UID != 1000 || resp.Status.Presence != "test" {
		t.Fatalf("status = %+v (%v)", resp, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if !strings.Contains(out.String(), "broker serving on platform-endpoint") {
		t.Fatalf("output = %q", out.String())
	}
}

type noPin struct{}

func (noPin) verify(*Identity) error { return nil }
func (noPin) close()                 {}
