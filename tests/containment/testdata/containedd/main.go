// Command containedd is a control-socket daemon for the containment tests of
// tier D5. It runs the real sandbox launcher with a fixed credential and sends
// every egress connection to one local server, so no provider is contacted.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
)

type fileAudit struct {
	mu sync.Mutex
	f  *os.File
}

func (a *fileAudit) Emit(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return json.NewEncoder(a.f).Encode(e)
}

// publicNames resolves every name to one public address, so the proxy's range
// checks pass and the dial hook decides where the connection really goes.
type publicNames struct{}

func (publicNames) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "localhost" {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func main() {
	var upstream, auditFile, secret, bin, runs, approve string
	flag.StringVar(&upstream, "upstream", "", "address every allowed egress connection is sent to")
	flag.StringVar(&auditFile, "audit", "", "file the audit events are appended to")
	flag.StringVar(&secret, "secret", "", "credential every field resolves to")
	flag.StringVar(&bin, "keylatch-bin", "", "keylatch executable used as the sandbox helper")
	flag.StringVar(&runs, "runs", "", "directory for the runs' private directories")
	flag.StringVar(&approve, "approve", "deny", "answer to approval requests: allow or deny")
	flag.Parse()
	if err := run(upstream, auditFile, secret, bin, runs, approve); err != nil {
		fmt.Fprintln(os.Stderr, "containedd:", err)
		os.Exit(1)
	}
}

func run(upstream, auditFile, secret, bin, runs, approve string) error {
	env := llmcontext.DefaultLookup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := registry.InitFromConfig(ctx, env); err != nil {
		return err
	}
	f, err := os.OpenFile(auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	socket := paths.ControlSocket(env)
	ln, err := control.Listen(socket)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(socket) }()

	cfg := control.Config{
		Env: env, Binary: "/bin/true", Audit: &fileAudit{f: f},
		Decide: func(context.Context, enforce.Request) enforce.Decision {
			return enforce.Decision{Allow: true, Source: "connection-policy"}
		},
		Approve: func(_ context.Context, r control.ApprovalRequest) (string, error) {
			if approve != "allow" {
				return "", errors.New("the test approver refuses")
			}
			return "apr-" + r.ArgvDigest()[:8], nil
		},
		Contained: &control.ContainedConfig{
			Launcher: &contained.Native{Binary: bin, Cgroups: true},
			Values:   func(context.Context, string, string) ([]byte, error) { return []byte(secret), nil },
			StateDir: runs,
			Resolver: publicNames{},
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, upstream)
			},
		},
	}
	return control.NewServer(cfg).Serve(ctx, ln)
}
