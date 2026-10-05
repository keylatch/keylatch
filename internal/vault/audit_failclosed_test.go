package vault_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
)

// switchableEmitter reports the audit log unavailable while down is set;
// failEmit makes only Emit fail, after Ready has passed.
type switchableEmitter struct {
	down     bool
	failEmit bool
}

func (e *switchableEmitter) Ready() error {
	if e.down {
		return fmt.Errorf("%w: test", audit.ErrUnavailable)
	}
	return nil
}

func (e *switchableEmitter) Emit(context.Context, audit.Event) error {
	if e.down || e.failEmit {
		return fmt.Errorf("%w: test", audit.ErrUnavailable)
	}
	return nil
}

const auditTestPath = "default/ai/openrouter/api_key"

func fileVaultWithSecret(t *testing.T) (config.Config, func(string) string, backend.Meta) {
	t.Helper()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	lookup := fileBackendEnv(t)
	meta := backend.Meta{Path: auditTestPath, Backend: "file", Version: 1}
	ctx, _ := testutil.WithAuditRecorder(context.Background())
	if err := vault.Set(ctx, auditTestPath, []byte("secret"), meta, cfg, lookup); err != nil {
		t.Fatal(err)
	}
	return cfg, lookup, meta
}

func TestVaultRefusesOperationsWhileAuditUnavailable(t *testing.T) {
	cfg, lookup, meta := fileVaultWithSecret(t)
	em := &switchableEmitter{down: true}
	ctx := audit.WithEmitter(context.Background(), em)

	if v, err := vault.Get(ctx, auditTestPath, cfg, lookup); !errors.Is(err, vault.ErrAuditFailed) || v != nil {
		t.Fatalf("Get while audit is down = %q, %v; want no value and ErrAuditFailed", v, err)
	}
	if err := vault.Set(ctx, auditTestPath, []byte("changed"), meta, cfg, lookup); !errors.Is(err, vault.ErrAuditFailed) {
		t.Fatalf("Set while audit is down = %v", err)
	}
	if err := vault.Delete(ctx, auditTestPath, cfg, lookup); !errors.Is(err, vault.ErrAuditFailed) {
		t.Fatalf("Delete while audit is down = %v", err)
	}
	if _, err := vault.List(ctx, "default/", cfg, lookup); !errors.Is(err, vault.ErrAuditFailed) {
		t.Fatalf("List while audit is down = %v", err)
	}

	em.down = false
	v, err := vault.Get(ctx, auditTestPath, cfg, lookup)
	if err != nil || string(v) != "secret" {
		t.Fatalf("Get once audit is back = %q, %v; want the unchanged secret", v, err)
	}
}

func TestVaultGetWithholdsValueWhenAuditWriteFails(t *testing.T) {
	cfg, lookup, _ := fileVaultWithSecret(t)
	ctx := audit.WithEmitter(context.Background(), &switchableEmitter{failEmit: true})
	if v, err := vault.Get(ctx, auditTestPath, cfg, lookup); !errors.Is(err, vault.ErrAuditFailed) || v != nil {
		t.Fatalf("Get with a failing audit write = %q, %v", v, err)
	}
}

func TestVaultRefusesReadsThroughClosedAuditLog(t *testing.T) {
	cfg, lookup, _ := fileVaultWithSecret(t)
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(filepath.Join(dir, "audit.log"), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := audit.WithEmitter(context.Background(), audit.AsEmitter(l))
	if _, err := vault.Get(ctx, auditTestPath, cfg, lookup); err != nil {
		t.Fatalf("Get with a working audit log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if v, err := vault.Get(ctx, auditTestPath, cfg, lookup); !errors.Is(err, audit.ErrLogClosed) || v != nil {
		t.Fatalf("Get through a closed audit log = %q, %v", v, err)
	}
}
