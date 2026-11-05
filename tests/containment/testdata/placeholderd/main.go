// Command placeholderd is a control-socket daemon for the containment tests.
// It serves tier D3 with a fixed credential and sends every upstream
// connection to one local TLS server, so no provider is ever contacted.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
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

type fixedResolver string

func (r fixedResolver) Resolve(context.Context, string, string) ([]byte, error) {
	return []byte(r), nil
}

func main() {
	var upstream, caFile, auditFile, canary string
	flag.StringVar(&upstream, "upstream", "", "address every upstream connection is sent to")
	flag.StringVar(&caFile, "upstream-ca", "", "PEM the upstream certificate is verified against")
	flag.StringVar(&auditFile, "audit", "", "file the audit events are appended to")
	flag.StringVar(&canary, "canary", "", "credential every field resolves to")
	flag.Parse()

	if err := run(upstream, caFile, auditFile, canary); err != nil {
		fmt.Fprintln(os.Stderr, "placeholderd:", err)
		os.Exit(1)
	}
}

func run(upstream, caFile, auditFile, canary string) error {
	env := llmcontext.DefaultLookup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := registry.InitFromConfig(ctx, env); err != nil {
		return err
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	f, err := os.OpenFile(auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	mgr, err := placeholder.NewManager(placeholder.Config{
		Resolver: fixedResolver(canary),
		Audit:    &fileAudit{f: f},
		Upstream: placeholder.Upstream{Roots: roots, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream)
		}},
	})
	if err != nil {
		return err
	}
	defer mgr.Close()

	socket := paths.ControlSocket(env)
	ln, err := control.Listen(socket)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(socket) }()
	return control.NewServer(control.Config{Env: env, Binary: "/bin/true", Placeholders: mgr}).Serve(ctx, ln)
}
