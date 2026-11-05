//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

func TestSessionTicketMakesACallerAnAgent(t *testing.T) {
	_, cfg := startDaemonWith(t, "", streamScript, nil)
	keyPath := paths.SessionTicketKey(lookupOf(cfg))
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{4}, 32)
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := llmcontext.IssueTicket(llmcontext.Ticket{SessionID: "s", PID: 1, ProcessStart: 1}, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewClient(lookupOf(cfg))
	c.ticket = raw
	resp, err := c.Exec(nil, "status", nil)
	if err != nil || resp.Kind != KindAgent {
		t.Fatalf("ticket holder = %+v %v", resp, err)
	}
	c.ticket = "not-a-ticket"
	if resp, _ := c.Exec(nil, "status", nil); resp.Kind != KindHuman {
		t.Fatalf("a bad ticket must change nothing, got %s", resp.Kind)
	}
}

func TestSplitVerb(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		global []string
		verb   string
		rest   []string
		ok     bool
	}{
		{[]string{"status"}, nil, "status", []string{}, true},
		{[]string{"--json", "list", "-n", "x"}, []string{"--json"}, "list", []string{"-n", "x"}, true},
		{[]string{"--log-level", "debug", "doctor"}, []string{"--log-level", "debug"}, "doctor", []string{}, true},
		{[]string{"--json"}, nil, "", nil, false},
		{[]string{"--", "status"}, nil, "", nil, false},
		{nil, nil, "", nil, false},
	} {
		global, verb, rest, ok := splitVerb(tc.args)
		if ok != tc.ok || verb != tc.verb || !slices.Equal(global, tc.global) || !slices.Equal(rest, tc.rest) {
			t.Errorf("%v = %v %q %v %v", tc.args, global, verb, rest, ok)
		}
	}
}

func TestRunTableSweepsRunsThatNeverReportedAnExit(t *testing.T) {
	var tab runTable
	old := &runState{id: "old", started: time.Now().Add(-3 * sessionTTL)}
	if expired := tab.add(old); len(expired) != 0 {
		t.Fatalf("expired = %v", expired)
	}
	fresh := &runState{id: "fresh", started: time.Now()}
	expired := tab.add(fresh)
	if len(expired) != 1 || expired[0].id != "old" {
		t.Fatalf("expired = %v", expired)
	}
	if tab.get("old") != nil || tab.take("fresh") != fresh || tab.take("fresh") != nil {
		t.Fatal("run table bookkeeping is wrong")
	}
	var none *runState
	none.relayed(10)
}

func TestFramesAreBounded(t *testing.T) {
	var v Request
	if err := readFrame(bufio.NewReader(strings.NewReader(strings.Repeat("a", 4096)+"\n")), &v, 1024); !errors.Is(err, errFrameTooLarge) {
		t.Errorf("oversized frame: %v", err)
	}
	if err := readFrame(bufio.NewReader(strings.NewReader("{not json}\n")), &v, 1024); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("malformed frame: %v", err)
	}
	var c Chunk
	var buf bytes.Buffer
	if err := writeFrame(&buf, Chunk{Data: bytes.Repeat([]byte{1}, chunkSize)}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() >= maxFrame {
		t.Fatalf("a full chunk frame is %d bytes, over the %d limit", buf.Len(), maxFrame)
	}
	if err := readFrame(bufio.NewReader(&buf), &c, maxFrame); err != nil || len(c.Data) != chunkSize {
		t.Fatalf("chunk round trip: %v %d", err, len(c.Data))
	}
}

func TestListenRefusesLooseDirectoryAndLiveDaemon(t *testing.T) {
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(loose, "k.sock")); err == nil {
		t.Error("a socket directory others can write was accepted")
	}
	d, _ := startDaemonWith(t, "", streamScript, nil)
	if _, err := Listen(d.socket); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Errorf("live daemon: %v", err)
	}
}

func TestAbandonIgnoresSessionsWithoutAProxy(t *testing.T) {
	s := NewServer(Config{})
	s.abandon(Response{})
	s.abandon(Response{Session: &Session{ProxyID: "x"}})
}
