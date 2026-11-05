package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/registry"
)

const probeTimeout = 30 * time.Second

// probeUpstream stands local servers in for provider hosts in tests; the zero
// value reaches the real hosts.
var probeUpstream placeholder.Upstream

// probeFunc sends one request toward url through the placeholder tier and
// returns the response status.
type probeFunc func(ctx context.Context, st connections.Store, em audit.Emitter, ns, name, url string) (int, error)

// probeTarget checks that rawURL is an https URL the binding's hosts cover.
func probeTarget(rawURL string, hosts []string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("--test-url must be an https URL without credentials")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	authority := net.JoinHostPort(u.Hostname(), port)
	for _, h := range hosts {
		if registry.MatchAuthority(h, authority) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("--test-url %s is outside the connection's hosts (%s)", authority, strings.Join(hosts, ", "))
}

// probeThroughPlaceholder opens a placeholder session for the connection and
// requests the URL with only the placeholder in the request. A matching status
// shows the stored value, the slots and the hosts agree, because the proxy
// replaced the placeholder with the real value on the way out.
func probeThroughPlaceholder(ctx context.Context, st connections.Store, em audit.Emitter, ns, name, rawURL string) (int, error) {
	if em == nil {
		return 0, errors.New("the audit log is unavailable, and a request that carries a credential is not sent without it")
	}
	tmpl, err := connections.CustomTemplate(ctx, st, ns, name)
	if err != nil {
		return 0, err
	}
	mgr, err := placeholder.NewManager(placeholder.Config{Resolver: storeResolver{st: st, ns: ns}, Audit: em, Upstream: probeUpstream})
	if err != nil {
		return 0, err
	}
	defer mgr.Close()
	sess, err := mgr.Open(placeholder.OpenRequest{Template: tmpl})
	if err != nil {
		return 0, err
	}
	defer sess.Close("probe finished")

	b, _ := tmpl.Binding()
	u, err := probeTarget(rawURL, b.Hosts)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	if err := applyPlaceholder(req, b, sess.Placeholders()); err != nil {
		return 0, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(sess.CAPEM()) {
		return 0, errors.New("the session CA could not be loaded")
	}
	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: "keylatch-session"}, nil },
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				near, far := net.Pipe()
				go sess.Serve(far)
				return near, nil
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// applyPlaceholder puts each field's placeholder where the binding says it
// goes toward the request's host.
func applyPlaceholder(req *http.Request, b registry.Binding, placeholders map[string]string) error {
	authority := req.URL.Host
	if req.URL.Port() == "" {
		authority = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	placed := false
	user, password := "", ""
	for field, value := range placeholders {
		for _, s := range b.SlotsFor(field, authority) {
			placed = true
			switch s.In {
			case registry.SlotHeader:
				req.Header.Set(s.Name, strings.TrimSpace(s.Scheme+" "+value))
			case registry.SlotQuery:
				q := req.URL.Query()
				q.Set(s.Name, value)
				req.URL.RawQuery = q.Encode()
			case registry.SlotBasic:
				if s.Part == registry.BasicUser {
					user = value
				} else {
					password = value
				}
			}
		}
	}
	if user != "" || password != "" {
		req.SetBasicAuth(user, password)
	}
	if !placed {
		return fmt.Errorf("no slot of the binding applies to %s", authority)
	}
	return nil
}

// storeResolver reads a custom connection's stored fields for the probe.
type storeResolver struct {
	st connections.Store
	ns string
}

func (r storeResolver) Resolve(ctx context.Context, connection, field string) ([]byte, error) {
	v, _, err := r.st.Get(ctx, connections.CustomSecretPath(r.ns, connection, field))
	return v, err
}

// runProbe checks the connection against in.TestURL and reports the outcome.
func runProbe(ctx context.Context, out io.Writer, st connections.Store, em audit.Emitter, name string, in customConnectInput) error {
	probe := in.Probe
	if probe == nil {
		probe = probeThroughPlaceholder
	}
	status, err := probe(ctx, st, em, in.Namespace, name, in.TestURL)
	if err != nil {
		return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: fmt.Sprintf("connect: test request failed: %v", err)}
	}
	if status != in.Expect {
		return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: fmt.Sprintf("connect: test request to %s returned %d, expected %d", in.TestURL, status, in.Expect)}
	}
	_, _ = fmt.Fprintf(out, "v %s — test request returned %d through the placeholder proxy\n", name, status)
	return nil
}
