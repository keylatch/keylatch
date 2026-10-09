package placeholder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
)

const (
	// bufferedBody is the largest request body read in full and scanned before
	// anything is sent upstream. Larger bodies are scanned as they stream.
	bufferedBody = 1 << 20

	// redirectWindow is how long a redirect target stays barred from
	// substitution after a response sent the caller there.
	redirectWindow = 30 * time.Second
)

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Alt-Svc",
}

// Serve speaks the HTTP proxy protocol on one client connection until it
// closes. The connection is the child's view of the proxy: CONNECT requests to
// bound hosts are terminated here, everything else is refused.
func (s *Session) Serve(conn net.Conn) {
	if !s.track(conn) {
		_ = conn.Close()
		return
	}
	defer s.untrack(conn)
	serveConn(conn, http.HandlerFunc(s.route))
}

type oneConn struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func (l *oneConn) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.addr }

// serveConn runs an HTTP server on a single, already established connection
// and returns once every handler has finished, including a hijacked one.
func serveConn(conn net.Conn, h http.Handler) {
	l := &oneConn{ch: make(chan net.Conn, 1), done: make(chan struct{}), addr: conn.LocalAddr()}
	l.ch <- conn
	var active sync.WaitGroup
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active.Add(1)
			defer active.Done()
			h.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				_ = l.Close()
			}
		},
	}
	_ = srv.Serve(l)
	active.Wait()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func splitTarget(hostport string) (host, port string, ok bool) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(hostport, ":") {
			return "", "", false
		}
		h, p = hostport, "443"
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	return h, p, h != "" && p != ""
}

func (s *Session) route(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.connect(w, r)
		return
	}
	s.plain(w, r)
}

// inactive answers a request that arrives after the session ended.
func (s *Session) inactive(w http.ResponseWriter) bool {
	s.mu.Lock()
	closed, suspended, expired := s.closed, s.suspended, time.Now().After(s.expires)
	s.mu.Unlock()
	switch {
	case suspended:
		writeError(w, http.StatusForbidden, "session_suspended", "this keylatch session was suspended after a placeholder was sent where it is not allowed")
	case closed || expired:
		writeError(w, http.StatusForbidden, "session_ended", "this keylatch session has ended")
	default:
		return false
	}
	return true
}

func (s *Session) denyEgress(w http.ResponseWriter, host, reason string) {
	_ = s.emit(audit.Event{Action: audit.ActionEgressDenied, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"provider": s.connection, "host": host, "reason": reason,
	}})
	writeError(w, http.StatusForbidden, "egress_denied", "keylatch: "+host+" is not reachable from this session")
}

// bound reports whether the session may substitute toward the authority.
func (s *Session) bound(authority string) bool {
	if !s.binding.AllowsHost(authority) {
		return false
	}
	return slices.ContainsFunc(s.entries, func(e *entry) bool {
		return len(s.binding.SlotsFor(e.field, authority)) > 0
	})
}

func (s *Session) connect(w http.ResponseWriter, r *http.Request) {
	if s.inactive(w) {
		return
	}
	host, port, ok := splitTarget(r.Host)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_target", "invalid CONNECT target")
		return
	}
	if net.ParseIP(host) != nil {
		s.denyEgress(w, host, "ip_literal")
		return
	}
	if !s.bound(net.JoinHostPort(host, port)) {
		s.denyEgress(w, host, "not_bound")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "hijack_unsupported", "connection cannot be taken over")
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	s.mitm(&bufferedConn{Conn: conn, r: brw.Reader}, host, port)
}

func (s *Session) mitm(conn net.Conn, host, port string) {
	tc := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi.ServerName != "" && !strings.EqualFold(chi.ServerName, host) {
				_ = s.emit(audit.Event{Action: audit.ActionEgressDenied, Outcome: audit.OutcomeDenied, Extra: map[string]any{
					"provider": s.connection, "host": host, "reason": "sni_mismatch",
				}})
				return nil, errors.New("SNI does not match the CONNECT target")
			}
			return s.ca.leaf(host)
		},
	})
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	serveConn(tc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.request(w, r, host, port)
	}))
}

func hostMatches(reqHost, host, port string) bool {
	h, p, err := net.SplitHostPort(reqHost)
	if err != nil {
		h, p = reqHost, "443"
	}
	return strings.ToLower(strings.TrimSuffix(h, ".")) == host && p == port
}

// finding is a placeholder seen where it must not be.
type finding struct{ where, field string }

type headerSub struct {
	name    string
	idx     int
	e       *entry
	rebuild func(real string) string
}

type querySub struct {
	idx int
	key string
	e   *entry
}

type plan struct {
	headers []headerSub
	query   []querySub
}

func (p *plan) entries() []*entry {
	var out []*entry
	add := func(e *entry) {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	for _, h := range p.headers {
		add(h.e)
	}
	for _, q := range p.query {
		add(q.e)
	}
	return out
}

func (p *plan) empty() bool { return len(p.headers) == 0 && len(p.query) == 0 }

// matchHeader reports whether value is exactly a placeholder in the position
// a slot declares, and how to rebuild it around the real credential.
func (s *Session) matchHeader(name, value, authority string) (*entry, func(string) string) {
	for _, e := range s.entries {
		for _, slot := range s.binding.SlotsFor(e.field, authority) {
			switch slot.In {
			case registry.SlotHeader:
				if !strings.EqualFold(slot.Name, name) {
					continue
				}
				if slot.Scheme == "" {
					if value == e.value {
						return e, func(real string) string { return real }
					}
					continue
				}
				prefix := slot.Scheme + " "
				if len(value) > len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) && value[len(prefix):] == e.value {
					lead := value[:len(prefix)]
					return e, func(real string) string { return lead + real }
				}
			case registry.SlotBasic:
				if !strings.EqualFold(name, "Authorization") || len(value) < 7 || !strings.EqualFold(value[:6], "Basic ") {
					continue
				}
				raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
				if err != nil {
					continue
				}
				user, pass, found := strings.Cut(string(raw), ":")
				if !found {
					continue
				}
				target, other := &user, pass
				if slot.Part == registry.BasicPassword {
					target, other = &pass, user
				}
				if *target != e.value || s.finder.inString(other) {
					continue
				}
				u, p := user, pass
				return e, func(real string) string {
					if slot.Part == registry.BasicPassword {
						p = real
					} else {
						u = real
					}
					return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
				}
			}
		}
	}
	return nil, nil
}

// plan finds every placeholder in the request head. A placeholder in a bound
// slot becomes a substitution; one anywhere else is a finding.
func (s *Session) plan(r *http.Request, authority string) (*plan, *finding) {
	p := &plan{}
	for name, values := range r.Header {
		if s.finder.inString(name) {
			return nil, &finding{where: "header_name"}
		}
		for i, v := range values {
			if e, rebuild := s.matchHeader(name, v, authority); e != nil {
				p.headers = append(p.headers, headerSub{name: name, idx: i, e: e, rebuild: rebuild})
				continue
			}
			if s.finder.inString(v) {
				return nil, &finding{where: "header:" + strings.ToLower(name)}
			}
		}
	}
	if s.finder.inString(r.URL.EscapedPath()) {
		return nil, &finding{where: "path"}
	}
	if r.URL.RawQuery != "" {
		for i, part := range strings.Split(r.URL.RawQuery, "&") {
			key, val, _ := strings.Cut(part, "=")
			k, kerr := url.QueryUnescape(key)
			v, verr := url.QueryUnescape(val)
			if kerr == nil && verr == nil {
				if e := s.queryEntry(k, v, authority); e != nil {
					p.query = append(p.query, querySub{idx: i, key: key, e: e})
					continue
				}
			}
			if s.finder.inString(part) {
				return nil, &finding{where: "query"}
			}
		}
	}
	if !p.empty() && s.redirectedTo(authority) {
		return nil, &finding{where: "redirect", field: p.entries()[0].field}
	}
	return p, nil
}

func (s *Session) queryEntry(name, value, authority string) *entry {
	for _, e := range s.entries {
		if e.value != value {
			continue
		}
		for _, slot := range s.binding.SlotsFor(e.field, authority) {
			if slot.In == registry.SlotQuery && slot.Name == name {
				return e
			}
		}
	}
	return nil
}

// headLeak reports where a placeholder appears in the request head, without
// regard to slots.
func (s *Session) headLeak(r *http.Request) string {
	for name, values := range r.Header {
		if s.finder.inString(name) {
			return "header_name"
		}
		for _, v := range values {
			if s.finder.inString(v) {
				return "header:" + strings.ToLower(name)
			}
		}
	}
	if s.finder.inString(r.URL.EscapedPath()) {
		return "path"
	}
	if s.finder.inString(r.URL.RawQuery) {
		return "query"
	}
	return ""
}

func (s *Session) redirectedTo(authority string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.redirects[authority]
	if ok && time.Now().After(until) {
		delete(s.redirects, authority)
		return false
	}
	return ok
}

func (s *Session) noteRedirect(from string, resp *http.Response) {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return
	}
	loc, err := resp.Location()
	if err != nil {
		return
	}
	port := loc.Port()
	if port == "" {
		port = "443"
		if loc.Scheme == "http" {
			port = "80"
		}
	}
	to := net.JoinHostPort(strings.ToLower(loc.Hostname()), port)
	if to == from {
		return
	}
	s.mu.Lock()
	s.redirects[to] = time.Now().Add(redirectWindow)
	s.mu.Unlock()
}

// misuse blocks the request, suspends the session and records the event.
func (s *Session) misuse(w http.ResponseWriter, host string, f finding) {
	s.mu.Lock()
	s.suspended = true
	conns := slices.Collect(func(yield func(net.Conn) bool) {
		for c := range s.conns {
			if !yield(c) {
				return
			}
		}
	})
	s.mu.Unlock()

	_ = s.emit(audit.Event{Action: audit.ActionPlaceholderMisuse, Outcome: audit.OutcomeDenied, Extra: map[string]any{
		"provider": s.connection, "field": f.field, "host": host, "where": f.where, "session_id_hmac": s.id,
	}})
	writeError(w, http.StatusForbidden, "placeholder_misuse", "keylatch: a placeholder was sent where it is not allowed; the session is suspended")
	time.AfterFunc(250*time.Millisecond, func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
}

func isUpgrade(r *http.Request) bool {
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

func (s *Session) request(w http.ResponseWriter, r *http.Request, host, port string) {
	if s.inactive(w) {
		return
	}
	authority := net.JoinHostPort(host, port)
	if strings.Contains(r.RequestURI, "://") {
		writeError(w, http.StatusBadRequest, "bad_request", "absolute-form request target inside a tunnel")
		return
	}
	if !hostMatches(r.Host, host, port) {
		if where := s.headLeak(r); where != "" {
			s.misuse(w, host, finding{where: "authority_mismatch:" + where})
			return
		}
		writeError(w, http.StatusMisdirectedRequest, "misdirected_request", "the request authority differs from the tunnel's host")
		return
	}

	p, f := s.plan(r, authority)
	if f != nil {
		s.misuse(w, host, *f)
		return
	}
	if isUpgrade(r) {
		writeError(w, http.StatusNotImplemented, "websocket_unsupported", "keylatch cannot substitute inside upgraded connections; use a typed action or a contained run")
		return
	}

	body, ok := s.checkBody(w, r, host)
	if !ok {
		return
	}

	real := map[string]string{}
	if !p.empty() {
		if err := s.consume(p.entries()); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, errExhausted) {
				status = http.StatusTooManyRequests
			}
			writeError(w, status, "placeholder_unavailable", "keylatch: "+err.Error())
			return
		}
		for _, e := range p.entries() {
			v, err := s.resolve(r.Context(), e.field)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "credential_unavailable", "keylatch: the credential could not be read")
				return
			}
			real[e.field] = v
		}
		if err := s.announce(host, p); err != nil {
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "keylatch: the audit log is not writable")
			return
		}
	}

	out := s.outbound(r, authority, p, real, body)
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		if sr, ok := body.(*scanReader); ok && (sr.hit || errors.Is(err, errLeak)) {
			s.misuse(w, host, finding{where: "body"})
			return
		}
		if errors.Is(err, errForbiddenTarget) {
			s.denyEgress(w, host, "restricted_destination")
			return
		}
		writeError(w, http.StatusBadGateway, "upstream_error", "keylatch: the upstream request failed")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if !p.empty() {
		s.noteRedirect(authority, resp)
	}
	s.relay(w, resp, p, real)
}

// checkBody returns the request body to send. A body that fits is read and
// scanned before anything leaves; a larger one is scanned as it streams.
func (s *Session) checkBody(w http.ResponseWriter, r *http.Request, host string) (io.Reader, bool) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return nil, true
	}
	if r.ContentLength > 0 && r.ContentLength <= bufferedBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, bufferedBody+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "the request body could not be read")
			return nil, false
		}
		if s.finder.in(data) {
			s.misuse(w, host, finding{where: "body"})
			return nil, false
		}
		return bytes.NewReader(data), true
	}
	return &scanReader{r: r.Body, f: s.finder}, true
}

func (s *Session) resolve(ctx context.Context, field string) (string, error) {
	val, err := s.cfg.Resolver.Resolve(ctx, s.connection, field)
	if err != nil {
		return "", err
	}
	defer clear(val)
	v := strings.TrimRight(string(val), "\r\n")
	if v == "" {
		return "", errors.New("empty credential")
	}
	return v, nil
}

// announce records the first substitution toward each host.
func (s *Session) announce(host string, p *plan) error {
	for _, e := range p.entries() {
		key := host + "\x00" + e.field
		s.mu.Lock()
		first := !s.announced[key]
		s.announced[key] = true
		s.mu.Unlock()
		if !first {
			continue
		}
		if err := s.emit(audit.Event{Action: audit.ActionProxySubstituted, Outcome: audit.OutcomeOK, Extra: map[string]any{
			"provider": s.connection, "field": e.field, "host": host, "count": 1,
		}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) outbound(r *http.Request, authority string, p *plan, real map[string]string, body io.Reader) *http.Request {
	h := r.Header.Clone()
	for _, name := range hopByHop {
		h.Del(name)
	}
	h.Del("Accept-Encoding")
	for _, c := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(tok))
		}
	}
	for _, hs := range p.headers {
		if vals := h[hs.name]; hs.idx < len(vals) {
			vals[hs.idx] = hs.rebuild(real[hs.e.field])
		}
	}
	u := &url.URL{Scheme: "https", Host: authority, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	if len(p.query) > 0 {
		parts := strings.Split(r.URL.RawQuery, "&")
		for _, q := range p.query {
			parts[q.idx] = q.key + "=" + url.QueryEscape(real[q.e.field])
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	out := &http.Request{
		Method:        r.Method,
		URL:           u,
		Host:          r.Host,
		Header:        h,
		ContentLength: r.ContentLength,
	}
	switch {
	case body == nil:
		out.Body = http.NoBody
	default:
		out.Body = io.NopCloser(body)
	}
	return out.WithContext(r.Context())
}

// relay copies the response to the client with the real credential replaced
// by its placeholder in the headers and the body.
func (s *Session) relay(w http.ResponseWriter, resp *http.Response, p *plan, real map[string]string) {
	var swaps []swap
	for _, e := range p.entries() {
		swaps = append(swaps, swap{old: []byte(real[e.field]), new: []byte(e.value)})
	}
	for k, vv := range resp.Header {
		if slices.ContainsFunc(hopByHop, func(h string) bool { return strings.EqualFold(h, k) }) {
			continue
		}
		if len(swaps) > 0 && strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, replaceAll(v, swaps))
		}
	}
	w.WriteHeader(resp.StatusCode)
	var src io.Reader = resp.Body
	if len(swaps) > 0 {
		src = newSwapReader(resp.Body, swaps)
	}
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

// plain handles a non-CONNECT request. Credentials are never sent in clear, so
// the only job is to refuse it and flag a placeholder that tried to leave.
func (s *Session) plain(w http.ResponseWriter, r *http.Request) {
	if s.inactive(w) {
		return
	}
	host := strings.ToLower(r.URL.Hostname())
	if r.URL.User != nil || s.finder.inString(r.URL.String()) || s.headLeak(r) != "" {
		s.misuse(w, host, finding{where: "plain_http"})
		return
	}
	if r.ContentLength > 0 && r.ContentLength <= bufferedBody {
		if data, err := io.ReadAll(io.LimitReader(r.Body, bufferedBody+1)); err == nil && s.finder.in(data) {
			s.misuse(w, host, finding{where: "plain_http_body"})
			return
		}
	}
	s.denyEgress(w, host, "plain_http")
}
