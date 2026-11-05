//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/exitcode"
)

// relayHarness runs relayContained against a scripted daemon on an in-memory
// connection.
type relayHarness struct {
	out, errOut bytes.Buffer
}

func (h *relayHarness) run(t *testing.T, in string, daemon func(r *bufio.Reader, conn net.Conn)) int {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close(); _ = far.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = far.Close() }()
		daemon(bufio.NewReader(far), far)
	}()
	req := Request{Op: OpContained, Run: &RunRequest{Connection: "stripe", Tier: TierContained, Command: []string{"make"}}}
	code := relayContained(context.Background(), near, req, nil, IO{In: strings.NewReader(in), Out: &h.out, ErrOut: &h.errOut})
	_ = near.Close()
	<-done
	return code
}

func readRequest(t *testing.T, r *bufio.Reader) Request {
	t.Helper()
	var req Request
	require.NoError(t, readFrame(r, &req, maxFrame))
	return req
}

func TestRelayContainedReportsARefusalBeforeTheRunStarts(t *testing.T) {
	var h relayHarness
	code := h.run(t, "", func(r *bufio.Reader, conn net.Conn) {
		req := readRequest(t, r)
		assert.Equal(t, OpContained, req.Op)
		assert.Equal(t, "stripe", req.Run.Connection)
		_ = writeFrame(conn, Response{Code: CodeRefused, ExitCode: exitcode.PolicyDeny, Error: "policy says no"})
	})
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, h.errOut.String(), "policy says no")
	assert.Empty(t, h.out.String())
}

func TestRelayContainedStreamsAnApprovedRunBothWays(t *testing.T) {
	var h relayHarness
	var sent strings.Builder
	code := h.run(t, "typed input", func(r *bufio.Reader, conn net.Conn) {
		readRequest(t, r)
		_ = writeFrame(conn, Response{More: true, Stderr: []byte("waiting for approval\n")})
		_ = writeFrame(conn, Response{More: true, Session: &Session{Tier: TierContained, RunID: "run-1"}})
		_ = writeFrame(conn, Response{More: true, Stdout: []byte("out-1 ")})
		_ = writeFrame(conn, Response{More: true, Stderr: []byte("err-1\n")})
		for {
			var c Chunk
			if err := readFrame(r, &c, maxFrame); err != nil {
				return
			}
			sent.Write(c.Data)
			if c.EOF {
				break
			}
		}
		_ = writeFrame(conn, Response{Stdout: []byte("out-2"), Stderr: []byte("err-2\n"), ExitCode: 3, Error: "the run failed"})
	})
	assert.Equal(t, 3, code)
	assert.Equal(t, "typed input", sent.String(), "stdin reaches the sandbox")
	assert.Equal(t, "out-1 out-2", h.out.String())
	for _, want := range []string{"waiting for approval", "err-1", "err-2", "the run failed"} {
		assert.Contains(t, h.errOut.String(), want)
	}
}

func TestRelayContainedTurnsAFailureWithoutAStatusIntoAnError(t *testing.T) {
	var h relayHarness
	code := h.run(t, "", func(r *bufio.Reader, conn net.Conn) {
		readRequest(t, r)
		_ = writeFrame(conn, Response{More: true, Session: &Session{RunID: "run-2"}})
		for {
			var c Chunk
			if readFrame(r, &c, maxFrame) != nil || c.EOF {
				break
			}
		}
		_ = writeFrame(conn, Response{OK: false})
	})
	assert.Equal(t, exitcode.OperationFailed, code)
}

func TestRelayContainedReportsADaemonThatHangsUp(t *testing.T) {
	var h relayHarness
	code := h.run(t, "", func(r *bufio.Reader, _ net.Conn) { readRequest(t, r) })
	assert.Equal(t, exitcode.OperationFailed, code)
	assert.Contains(t, h.errOut.String(), "daemon:")
}

func TestRelayContainedReportsARequestThatCannotBeSent(t *testing.T) {
	near, far := net.Pipe()
	require.NoError(t, far.Close())
	var out, errOut bytes.Buffer
	req := Request{Op: OpContained, Run: &RunRequest{Connection: "stripe"}}
	code := relayContained(context.Background(), near, req, nil, IO{In: strings.NewReader(""), Out: &out, ErrOut: &errOut})
	assert.Equal(t, exitcode.OperationFailed, code)
	assert.Contains(t, errOut.String(), "daemon:")
}

func TestRelayInputForwardsEndOfInputAndSignals(t *testing.T) {
	var mu sync.Mutex
	var got []Chunk
	send := func(c Chunk) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, c)
	}
	snapshot := func() []Chunk {
		mu.Lock()
		defer mu.Unlock()
		return append([]Chunk(nil), got...)
	}
	has := func(match func(Chunk) bool) func() bool {
		return func() bool {
			for _, c := range snapshot() {
				if match(c) {
					return true
				}
			}
			return false
		}
	}

	stop := relayInput(context.Background(), IO{In: strings.NewReader("abc")}, false, nil, send)
	defer stop()
	require.Eventually(t, has(func(c Chunk) bool { return c.EOF }), 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, has(func(c Chunk) bool { return string(c.Data) == "abc" }), 5*time.Second, 5*time.Millisecond)

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
	require.Eventually(t, has(func(c Chunk) bool { return c.Signal == int(syscall.SIGHUP) }), 5*time.Second, 5*time.Millisecond, "a hangup is forwarded to the sandbox")
}

func TestRelayInputWithoutStdinStillEndsTheInput(t *testing.T) {
	ended := make(chan struct{})
	stop := relayInput(context.Background(), IO{}, true, nil, func(c Chunk) {
		if c.EOF {
			close(ended)
		}
	})
	defer stop()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("no end-of-input frame")
	}
}
