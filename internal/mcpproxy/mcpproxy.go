// Package mcpproxy lets an agent use a remote MCP server that needs a bearer
// token without holding the token. The agent's MCP client starts the proxy as
// a stdio server; the proxy forwards each JSON-RPC message to the remote
// Streamable HTTP endpoint and adds the credential from the connection's
// store, so the agent's configuration names a connection and a URL only.
package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/redactor"
	"github.com/keylatch/keylatch/internal/registry"
)

const (
	// maxMessage bounds one JSON-RPC message in either direction.
	maxMessage     = 8 << 20
	requestTimeout = 5 * time.Minute
)

// Config describes one proxy.
type Config struct {
	// URL is the remote MCP endpoint. Its host must be one of the
	// connection's bound hosts, and it must use https unless it is a
	// loopback address.
	URL        string
	Connection string
	Binding    registry.Binding
	// Secret returns the stored value of a connection field.
	Secret func(ctx context.Context, field string) ([]byte, error)
	// Authorize is asked once before the first request.
	Authorize func(ctx context.Context) error
	Caller    callerkind.Kind
	// Audit receives one event per forwarded request. Requests are refused
	// when it cannot record them.
	Audit audit.Emitter
	// HTTP is the client used for the remote server; the default never
	// follows a redirect, so the token cannot leave the bound host.
	HTTP *http.Client
}

// Run reads newline-delimited JSON-RPC messages from in until it ends and
// writes the remote server's answers to out.
func Run(ctx context.Context, cfg Config, in io.Reader, out io.Writer) error {
	p, err := newProxy(cfg)
	if err != nil {
		return err
	}
	if cfg.Authorize != nil {
		if err := cfg.Authorize(ctx); err != nil {
			return err
		}
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), maxMessage)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		p.forward(ctx, append([]byte(nil), line...), out)
	}
	return sc.Err()
}

type proxy struct {
	cfg     Config
	target  *url.URL
	slot    registry.Slot
	client  *http.Client
	session string
}

func newProxy(cfg Config) (*proxy, error) {
	target, err := url.Parse(cfg.URL)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("mcpproxy: %q is not a URL", cfg.URL)
	}
	if target.Scheme != "https" && (target.Scheme != "http" || !isLoopback(target.Hostname())) {
		return nil, fmt.Errorf("mcpproxy: %s must use https; the credential is not sent in the clear", cfg.URL)
	}
	if target.User != nil {
		return nil, errors.New("mcpproxy: the URL may not carry credentials")
	}
	slot, err := headerSlot(cfg.Binding, target)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &proxy{cfg: cfg, target: target, slot: slot, client: &c}, nil
}

// headerSlot picks the header slot that is bound to the target's host.
func headerSlot(b registry.Binding, target *url.URL) (registry.Slot, error) {
	authority := target.Host
	if target.Port() == "" {
		authority = net.JoinHostPort(target.Hostname(), map[string]string{"https": "443", "http": "80"}[target.Scheme])
	}
	for _, s := range b.Slots {
		if s.In != registry.SlotHeader {
			continue
		}
		for _, h := range s.Hosts {
			if registry.MatchAuthority(h, authority) {
				return s, nil
			}
		}
	}
	return registry.Slot{}, fmt.Errorf("mcpproxy: %s is outside the hosts the connection's header slots are bound to", target.Host)
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (p *proxy) forward(ctx context.Context, msg []byte, out io.Writer) {
	id, method := identify(msg)
	if err := audit.Ready(p.cfg.Audit); err != nil {
		if id != nil {
			writeError(out, id, "the audit log is not available; Keylatch does not forward unaudited requests")
		}
		return
	}
	status, replies, err := p.post(ctx, msg)
	reason := ""
	if err != nil {
		reason = "forward_failed"
	}
	if aerr := p.audit(ctx, method, status, reason); aerr != nil {
		if id != nil {
			writeError(out, id, "the audit log is not available; Keylatch does not forward unaudited requests")
		}
		return
	}
	if err != nil {
		if id != nil {
			writeError(out, id, err.Error())
		}
		return
	}
	for _, r := range replies {
		_, _ = out.Write(append(r, '\n'))
	}
}

// post sends one message and returns the messages of the answer.
func (p *proxy) post(ctx context.Context, msg []byte) (int, [][]byte, error) {
	token, err := p.cfg.Secret(ctx, p.slot.Field)
	if err != nil || len(token) == 0 {
		return 0, nil, fmt.Errorf("the connection %s has no %s", p.cfg.Connection, p.slot.Field)
	}
	defer clear(token)
	matcher := redactor.NewMatcher(token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.target.String(), bytes.NewReader(msg))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if p.session != "" {
		req.Header.Set("Mcp-Session-Id", p.session)
	}
	value := string(token)
	if p.slot.Scheme != "" {
		value = p.slot.Scheme + " " + value
	}
	req.Header.Set(p.slot.Name, value)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("the remote MCP server is unreachable: %s", matcher.Redact([]byte(err.Error())))
	}
	defer func() { _ = resp.Body.Close() }()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		p.session = s
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil, nil
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, nil, fmt.Errorf("the remote MCP server answered %d", resp.StatusCode)
	}
	replies, err := readReplies(io.LimitReader(resp.Body, maxMessage), resp.Header.Get("Content-Type"))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	for i, r := range replies {
		// An answer that echoes the token is not passed on with it.
		replies[i] = matcher.Redact(r)
	}
	return resp.StatusCode, replies, nil
}

// readReplies returns the JSON-RPC messages of a JSON or event-stream body,
// each compacted onto one line as the stdio transport requires.
func readReplies(body io.Reader, contentType string) ([][]byte, error) {
	var out [][]byte
	add := func(raw []byte) error {
		var buf bytes.Buffer
		if err := json.Compact(&buf, raw); err != nil {
			return fmt.Errorf("the remote MCP server sent a message that is not JSON: %w", err)
		}
		out = append(out, buf.Bytes())
		return nil
	}
	if !strings.HasPrefix(contentType, "text/event-stream") {
		raw, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, nil
		}
		return out, add(raw)
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), maxMessage)
	var data []byte
	flush := func() error {
		if len(data) == 0 {
			return nil
		}
		raw := data
		data = nil
		return add(raw)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "data:"):
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")...)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, flush()
}

func (p *proxy) audit(ctx context.Context, method string, status int, reason string) error {
	if err := audit.Ready(p.cfg.Audit); err != nil {
		return err
	}
	outcome := audit.OutcomeOK
	if reason != "" {
		outcome = audit.OutcomeError
	}
	extra := map[string]any{
		"connection":  p.cfg.Connection,
		"action":      "mcp." + method,
		"caller_kind": string(p.cfg.Caller),
		"status":      status,
	}
	if reason != "" {
		extra["reason"] = reason
	}
	return p.cfg.Audit.Emit(ctx, audit.Event{Timestamp: time.Now().UTC(), Action: audit.ActionCall, Outcome: outcome, Extra: extra})
}

// identify reads the request id and method of a message. A message without an
// id is a notification and gets no error reply.
func identify(msg []byte) (id json.RawMessage, method string) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(msg, &m) != nil || m.Method == "" {
		return nil, "message"
	}
	if len(m.ID) == 0 || string(m.ID) == "null" {
		return nil, m.Method
	}
	return m.ID, m.Method
}

func writeError(out io.Writer, id json.RawMessage, message string) {
	reply, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": -32603, "message": message},
	})
	_, _ = out.Write(append(reply, '\n'))
}
