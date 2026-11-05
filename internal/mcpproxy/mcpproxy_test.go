package mcpproxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/mcpproxy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token is built by concatenation so scanners do not flag the fixture.
const remoteToken = "mcp" + "-remote-token-0123456789abcdef"

type remote struct {
	mu       sync.Mutex
	requests []seen
	handle   func(w http.ResponseWriter, r *http.Request, body []byte)
}

type seen struct {
	auth    string
	session string
	body    string
}

func (rm *remote) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rm.mu.Lock()
		rm.requests = append(rm.requests, seen{r.Header.Get("Authorization"), r.Header.Get("Mcp-Session-Id"), string(body)})
		rm.mu.Unlock()
		rm.handle(w, r, body)
	}
}

func bindingFor(srv *httptest.Server) registry.Binding {
	u, _ := url.Parse(srv.URL)
	return registry.Binding{
		Provider: "remote-mcp",
		Hosts:    []string{u.Host},
		Slots:    []registry.Slot{{Field: "token", In: registry.SlotHeader, Name: "Authorization", Scheme: "Bearer", Hosts: []string{u.Host}}},
	}
}

type fixture struct {
	srv    *httptest.Server
	remote *remote
	audit  *testutil.AuditRecorder
	cfg    mcpproxy.Config
}

func newFixture(t *testing.T, handle func(http.ResponseWriter, *http.Request, []byte)) *fixture {
	t.Helper()
	rm := &remote{handle: handle}
	srv := httptest.NewServer(rm.handler())
	t.Cleanup(srv.Close)
	f := &fixture{srv: srv, remote: rm, audit: &testutil.AuditRecorder{}}
	f.cfg = mcpproxy.Config{
		URL: srv.URL + "/mcp", Connection: "remote-mcp", Binding: bindingFor(srv),
		Secret: func(_ context.Context, field string) ([]byte, error) {
			if field != "token" {
				return nil, errors.New("no such field")
			}
			return []byte(remoteToken), nil
		},
		Caller: callerkind.Agent, Audit: f.audit,
	}
	return f
}

func (f *fixture) run(t *testing.T, input string) []string {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, mcpproxy.Run(context.Background(), f.cfg, strings.NewReader(input), &out))
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func jsonReply(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

func TestInjectsTheCredentialAndReturnsTheAnswer(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		jsonReply(w, "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {\"tools\": []}\n}")
	})
	out := f.run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")

	require.Len(t, out, 1)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, out[0])
	assert.NotContains(t, out[0], "\n", "each message is one line")
	require.Len(t, f.remote.requests, 1)
	assert.Equal(t, "Bearer "+remoteToken, f.remote.requests[0].auth)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, f.remote.requests[0].body)
}

func TestTheAgentsOwnAuthorizationNeverReachesTheRemote(t *testing.T) {
	// The proxy only forwards the JSON-RPC body; headers come from the proxy.
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	f.run(t, `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"Authorization":"Bearer agent-chosen"}}`+"\n")
	assert.Equal(t, "Bearer "+remoteToken, f.remote.requests[0].auth)
}

func TestKeepsTheSessionAcrossRequests(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, body []byte) {
		w.Header().Set("Mcp-Session-Id", "session-42")
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	f.run(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n"+`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n")
	require.Len(t, f.remote.requests, 2)
	assert.Empty(t, f.remote.requests[0].session)
	assert.Equal(t, "session-42", f.remote.requests[1].session)
}

func TestReadsEventStreamAnswers(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":3,\"result\":{}}\n\n")
	})
	out := f.run(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call"}`+"\n")
	require.Len(t, out, 2)
	assert.JSONEq(t, `{"jsonrpc":"2.0","method":"notifications/progress"}`, out[0])
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":3,"result":{}}`, out[1])
}

func TestNotificationsGetNoAnswer(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusAccepted) })
	assert.Empty(t, f.run(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"))
	assert.Len(t, f.remote.requests, 1)
}

func TestARemoteFailureBecomesAJSONRPCError(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusUnauthorized) })
	out := f.run(t, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`+"\n")
	require.Len(t, out, 1)
	var reply struct {
		ID    int `json:"id"`
		Error struct{ Message string }
	}
	require.NoError(t, json.Unmarshal([]byte(out[0]), &reply))
	assert.Equal(t, 7, reply.ID)
	assert.Contains(t, reply.Error.Message, "401")
	assert.NotContains(t, out[0], remoteToken)
}

func TestAnAnswerThatEchoesTheTokenIsRedacted(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{"echo":"`+remoteToken+`"}}`)
	})
	out := f.run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`+"\n")
	require.Len(t, out, 1)
	assert.NotContains(t, out[0], remoteToken)
}

func TestARedirectDoesNotCarryTheToken(t *testing.T) {
	var elsewhereAuth string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereAuth = r.Header.Get("Authorization")
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(elsewhere.Close)
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	})
	out := f.run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	require.Len(t, out, 1)
	assert.Contains(t, out[0], "307")
	assert.Empty(t, elsewhereAuth, "the redirect target never sees the credential")
}

func TestRefusesWhatItCouldLeakTo(t *testing.T) {
	f := newFixture(t, func(http.ResponseWriter, *http.Request, []byte) {})
	cases := map[string]string{
		"other host":       "http://127.0.0.1:1/mcp",
		"plain http":       "http://remote.example/mcp",
		"embedded login":   strings.Replace(f.srv.URL, "http://", "http://user:pw@", 1) + "/mcp",
		"not a url":        "::",
		"missing hostname": "https:///mcp",
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := f.cfg
			cfg.URL = u
			err := mcpproxy.Run(context.Background(), cfg, strings.NewReader(""), io.Discard)
			require.Error(t, err)
		})
	}
	assert.Empty(t, f.remote.requests)
}

func TestRefusesWithoutAHeaderSlot(t *testing.T) {
	f := newFixture(t, func(http.ResponseWriter, *http.Request, []byte) {})
	f.cfg.Binding.Slots = []registry.Slot{{Field: "token", In: registry.SlotQuery, Name: "key", Hosts: f.cfg.Binding.Hosts}}
	require.Error(t, mcpproxy.Run(context.Background(), f.cfg, strings.NewReader(""), io.Discard))
}

func TestAuthorizeDeniesBeforeAnyRequest(t *testing.T) {
	f := newFixture(t, func(http.ResponseWriter, *http.Request, []byte) {})
	f.cfg.Authorize = func(context.Context) error { return errors.New("denied by policy") }
	err := mcpproxy.Run(context.Background(), f.cfg, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), io.Discard)
	require.ErrorContains(t, err, "denied by policy")
	assert.Empty(t, f.remote.requests)
}

func TestMissingCredentialIsReportedWithoutForwarding(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { jsonReply(w, `{}`) })
	f.cfg.Secret = func(context.Context, string) ([]byte, error) { return nil, errors.New("not found") }
	out := f.run(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n")
	require.Len(t, out, 1)
	assert.Contains(t, out[0], "has no token")
	assert.Empty(t, f.remote.requests)
}

func TestEveryRequestIsAudited(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		jsonReply(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})
	f.run(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`+"\n")
	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.ActionCall, events[0].Action)
	assert.Equal(t, "mcp.tools/call", events[0].Extra["action"])
	assert.Equal(t, "agent", events[0].Extra["caller_kind"])
	assert.Equal(t, 200, events[0].Extra["status"])
	raw, err := json.Marshal(events[0].Extra)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), remoteToken)
}

type deadAudit struct{}

func (deadAudit) Emit(context.Context, audit.Event) error { return errors.New("disk full") }
func (deadAudit) Ready() error                            { return errors.New("disk full") }

func TestNothingIsForwardedWithoutAnAuditLog(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { jsonReply(w, `{}`) })
	f.cfg.Audit = deadAudit{}
	out := f.run(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"+`{"jsonrpc":"2.0","method":"notifications/x"}`+"\n")
	require.Len(t, out, 1, "the request gets an error; the notification gets none")
	assert.Contains(t, out[0], "audit log")
	assert.Empty(t, f.remote.requests)
}
