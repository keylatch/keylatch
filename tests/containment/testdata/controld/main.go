// Command controld is a control-socket daemon for the containment tests. It
// serves the daemon-served verbs and tier D2 like keylatchd, but records its
// audit events in a plain file so tests can read them.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
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

func main() {
	var bin, auditFile string
	flag.StringVar(&bin, "keylatch-bin", "", "keylatch executable the served verbs run")
	flag.StringVar(&auditFile, "audit", "", "file the audit events are appended to")
	flag.Parse()
	if err := run(bin, auditFile); err != nil {
		fmt.Fprintln(os.Stderr, "controld:", err)
		os.Exit(1)
	}
}

func run(bin, auditFile string) error {
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
	defer func() { _ = f.Close() }()

	socket := paths.ControlSocket(env)
	ln, err := control.Listen(socket)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(socket) }()
	return control.NewServer(control.Config{Env: env, Binary: bin, Audit: &fileAudit{f: f}}).Serve(ctx, ln)
}
