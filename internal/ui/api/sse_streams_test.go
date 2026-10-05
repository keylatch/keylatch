package api_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/approval"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxStream runs h in the background against a pipe-backed writer and returns
// a channel of SSE lines plus a cancel func that ends the request and waits
// for the handler to return.
func mxStream(t *testing.T, h http.Handler, path string) (<-chan string, func()) {
	t.Helper()
	pr, pw := io.Pipe()
	w := &pipeResponseWriter{pw: pw, header: make(http.Header), code: http.StatusOK}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, req)
		_ = pw.Close()
	}()

	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	stop := func() {
		cancel()
		// Drain so a blocked pipe write cannot keep the handler alive.
		go func() {
			for range lines { //nolint:revive // draining
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("stream handler did not return after cancel")
		}
	}
	return lines, stop
}

func mxWaitLine(t *testing.T, lines <-chan string, substr string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("stream closed before %q", substr)
			}
			if strings.Contains(l, substr) {
				return l
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", substr)
		}
	}
}

func TestReceiptsStream_DeliversPushedReceiptValueFree(t *testing.T) {
	store := api.NewReceiptStore(4)
	lines, stop := mxStream(t, api.NewReceiptsStreamHandler(store), "/v1/receipts/stream")
	defer stop()

	// The handler subscribes before emitting the heartbeat, so a push after
	// the heartbeat is guaranteed to be delivered.
	mxWaitLine(t, lines, "event: heartbeat")
	store.Push(runner.RuntimeReceipt{
		Runtime:         "gateway_typed",
		Provider:        "anthropic",
		Capability:      "messages",
		PolicyDecision:  "allowed",
		CredentialShape: "bearer",
		ExitCode:        3,
		TTL:             time.Second,
	})
	mxWaitLine(t, lines, "event: receipt")
	data := mxWaitLine(t, lines, "data:")
	assert.Contains(t, data, `"provider":"anthropic"`)
	assert.Contains(t, data, `"exit_code":3`)
	assert.Contains(t, data, `"ttl":1000000000`)
}

func TestReceiptsStream_NilStoreSendsHeartbeatOnly(t *testing.T) {
	lines, stop := mxStream(t, api.NewReceiptsStreamHandler(nil), "/v1/receipts/stream")
	mxWaitLine(t, lines, "event: heartbeat")
	stop()
}

func TestReceiptsStream_NonFlusherRejected(t *testing.T) {
	t.Parallel()
	w := &mxNoFlushWriter{header: http.Header{}}
	api.NewReceiptsStreamHandler(api.NewReceiptStore(1)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/receipts/stream", nil))
	assert.Equal(t, http.StatusInternalServerError, w.code)
}

func TestReceiptsStream_UnsubscribeOnDisconnect(t *testing.T) {
	store := api.NewReceiptStore(4)
	lines, stop := mxStream(t, api.NewReceiptsStreamHandler(store), "/v1/receipts/stream")
	mxWaitLine(t, lines, "event: heartbeat")
	stop()
	// After the subscriber is gone, Push must neither block nor panic.
	store.Push(runner.RuntimeReceipt{Provider: "after-close"})
	require.Len(t, store.Last(0), 1)
}

func TestAdminSSE_GlobalBusDeliversPublishApproval(t *testing.T) {
	h := &api.AdminApprovalsSSEHandler{Team: newTestTeam()}
	lines, stop := mxStream(t, h, "/admin/approvals/stream")
	defer stop()
	mxWaitLine(t, lines, "event: heartbeat")

	req, err := approval.Create(context.Background(), "write", "prod:db", team.Member{
		ID: "requester", HMAC: "hmac-global-bus", Role: team.RoleDeveloper,
	}, approval.ModeTwoPerson, 2, 2)
	require.NoError(t, err)

	// The handler subscribes after its first heartbeat; republish until the
	// event arrives instead of guessing a delay.
	got := make(chan string, 1)
	go func() {
		for l := range lines {
			if strings.Contains(l, "hmac-global-bus") {
				got <- l
				return
			}
		}
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case l := <-got:
			assert.Contains(t, l, `"capability":"write"`)
			assert.Contains(t, l, `"connection":"prod:db"`)
			assert.NotContains(t, l, `:"requester"`)
			return
		case <-tick.C:
			api.PublishApproval(req)
		case <-deadline:
			t.Fatal("approval event not delivered on global bus")
		}
	}
}

func TestApprovalsStream_ReportsUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	(&api.ApprovalsHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/approvals/stream", nil))
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_implemented")
}

func TestApprovalsHandler_Routing(t *testing.T) {
	t.Parallel()
	h := &api.ApprovalsHandler{}
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/approvals", http.StatusNotImplemented},
		{http.MethodGet, "/api/approvals/stream", http.StatusNotImplemented},
		{http.MethodPost, "/api/approvals", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/approvals/stream", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/approvals/tok/explode", http.StatusNotFound},
		{http.MethodGet, "/api/approvals/tok/approve", http.StatusNotFound},
		{http.MethodPost, "/api/approvals/tok/deny", http.StatusNotImplemented},
		{http.MethodPost, "/api/approvals/tok/approve", http.StatusNotImplemented},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, tc.want, rec.Code, "%s %s", tc.method, tc.path)
	}
}
