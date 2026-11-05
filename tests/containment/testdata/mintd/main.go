// Command mintd is a control-socket daemon for the containment tests. It
// serves tier D3 for a GitHub App connection: tokens come from a fake App API
// it hosts itself, and every upstream connection goes to one local TLS server.
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
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/mintsession/mintsessiontest"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/mint"
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

type noStore struct{}

func (noStore) Resolve(context.Context, string, string) ([]byte, error) {
	return nil, fmt.Errorf("no stored credentials")
}

func main() {
	var upstream, caFile, auditFile, apiLog string
	flag.StringVar(&upstream, "upstream", "", "address every upstream connection is sent to")
	flag.StringVar(&caFile, "upstream-ca", "", "PEM the upstream certificate is verified against")
	flag.StringVar(&auditFile, "audit", "", "file the audit events are appended to")
	flag.StringVar(&apiLog, "api-log", "", "file the fake App API logs mints and revocations to")
	flag.Parse()
	if err := run(upstream, caFile, auditFile, apiLog); err != nil {
		fmt.Fprintln(os.Stderr, "mintd:", err)
		os.Exit(1)
	}
}

func run(upstream, caFile, auditFile, apiLog string) error {
	lookup := llmcontext.DefaultLookup
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := registry.InitFromConfig(ctx, lookup); err != nil {
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
	logf, err := os.OpenFile(apiLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	em := &fileAudit{f: f}

	api := mintsessiontest.NewStub()
	defer api.Close()
	api.Log = logf
	store, err := mintsessiontest.NewStore()
	if err != nil {
		return err
	}
	cfg := config.Default()
	cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: &config.GitHubAppMintPolicy{
		PlaceholderCallers: []string{"agent", "host"},
		AllowOwners:        []string{mintsessiontest.Owner},
		PermissionCeiling:  map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"},
	}}}}
	minter := mintsession.New(mintsession.Config{Store: store, APIBase: api.URL, Audit: em, Policy: func() (config.Config, error) { return cfg, nil }})

	mgr, err := placeholder.NewManager(placeholder.Config{
		Resolver: noStore{},
		Audit:    em,
		Upstream: placeholder.Upstream{Roots: roots, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream)
		}},
	})
	if err != nil {
		return err
	}
	defer mgr.Close()

	socket := paths.ControlSocket(lookup)
	ln, err := control.Listen(socket)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(socket) }()
	return control.NewServer(control.Config{
		Env: lookup, Binary: "/bin/true", Placeholders: mgr,
		Mint: func(ctx context.Context, kind control.Kind, rr *control.RunRequest) (placeholder.Credential, error) {
			cred, err := minter.Open(ctx, mintsession.Request{
				Connection: rr.Connection, Repository: rr.Repository, Permissions: rr.Permissions, Caller: mint.CallerKind(kind),
			})
			if err != nil {
				return nil, err
			}
			return cred, nil
		},
	}).Serve(ctx, ln)
}
