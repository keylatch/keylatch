//go:build unix

package cli

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type caSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *caSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *caSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func caWaitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAuditTailFollowStreamsNewEventsUntilInterrupted(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, audit.Event{Action: audit.ActionList, Outcome: audit.OutcomeOK, Backend: "earlier"})

	out := &caSyncBuffer{}
	root := NewRootCommand()
	root.SetOut(out)
	root.SetErr(&caSyncBuffer{})
	root.SetArgs([]string{"audit", "tail", "-f"})
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(context.Background()) }()

	caWaitFor(t, func() bool { return strings.Contains(out.String(), "TIMESTAMP") }, "follow header")
	assert.Contains(t, out.String(), "Watching audit log. Press Ctrl-C to stop.")

	caLogEvents(t, audit.Event{Action: audit.ActionRevoke, Outcome: audit.OutcomeDenied, Backend: "followed"})
	caWaitFor(t, func() bool { return strings.Contains(out.String(), "followed") }, "followed event")

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("tail -f did not stop on SIGINT")
	}
	assert.NotContains(t, out.String(), "earlier", "follow mode only prints events appended after start")
	assert.Contains(t, out.String(), "revoke")
}

func TestAuditTailFollowJSON(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, audit.Event{Action: audit.ActionList, Outcome: audit.OutcomeOK})

	out := &caSyncBuffer{}
	root := NewRootCommand()
	root.SetOut(out)
	root.SetErr(&caSyncBuffer{})
	root.SetArgs([]string{"audit", "tail", "-f", "--json"})
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(context.Background()) }()

	// No header in JSON mode, so keep appending until the follower reports one.
	caWaitFor(t, func() bool {
		if strings.Contains(out.String(), `"backend":"json-follow"`) {
			return true
		}
		caLogEvents(t, audit.Event{Action: audit.ActionRead, Outcome: audit.OutcomeOK, Backend: "json-follow"})
		time.Sleep(300 * time.Millisecond)
		return false
	}, "json event")

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("tail -f --json did not stop on SIGINT")
	}
	assert.NotContains(t, out.String(), "TIMESTAMP")
}
