package cli

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/audit/salt"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

var auditTestLookup = llmcontext.DefaultLookup

func bootstrapForAudit(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keylatch")
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	testutil.ClearLLMSessionEnv(t)
	if _, err := bootstrap.Run(context.Background(), bootstrap.Options{Backend: "file", Env: auditTestLookup}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return dir
}

func logOne(t *testing.T, l *audit.Logger) {
	t.Helper()
	if err := l.Log(context.Background(), audit.Event{Action: audit.ActionGatewayCall, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatal(err)
	}
}

func verifyAuditLog(t *testing.T) audit.ChainReport {
	t.Helper()
	dek, older, err := loadAuditKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := salt.LoadOrCreate(paths.AuditSalt(auditTestLookup))
	if err != nil {
		t.Fatal(err)
	}
	report, err := audit.VerifyChain(paths.Audit(auditTestLookup), s, dek, older...)
	if err != nil {
		t.Fatal(err)
	}
	if report.FirstBadLine != 0 {
		t.Fatalf("audit chain broken at line %d: %s", report.FirstBadLine, report.FirstBadReason)
	}
	return report
}

func TestAuditWorksRightAfterBootstrap(t *testing.T) {
	dir := bootstrapForAudit(t)

	// gateway up opens its audit logger through openAuditLogger.
	l, cleanup, err := openAuditLogger()
	if err != nil {
		t.Fatalf("audit logger unavailable right after bootstrap: %v", err)
	}
	logOne(t, l)
	cleanup()

	if report := verifyAuditLog(t); report.TotalLines != 1 {
		t.Fatalf("verified %d lines, want 1", report.TotalLines)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault", "keyring", "keyring.json")); !os.IsNotExist(err) {
		t.Fatalf("a second keyring was created under the vault: %v", err)
	}
}

func TestAuditReadsEventsSealedWithLegacyKeyring(t *testing.T) {
	bootstrapForAudit(t)

	legacy := paths.LegacyKeyringPath(auditTestLookup)
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	legacySalt := make([]byte, 32)
	if _, err := rand.Read(legacySalt); err != nil {
		t.Fatal(err)
	}
	k, err := kek.AgeIdentityKEKFromPath(paths.KeyringIdentityPath(auditTestLookup), legacySalt)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.NewWithSalt(legacy, k, envelope.XChaCha20Poly1305, 0, legacySalt); err != nil {
		t.Fatal(err)
	}
	lkr, _, _, err := openKeyringAt(legacy, false)
	if err != nil {
		t.Fatal(err)
	}
	legacyDEK, _, err := lkr.ActiveDEK()
	if err != nil {
		t.Fatal(err)
	}
	s, err := salt.LoadOrCreate(paths.AuditSalt(auditTestLookup))
	if err != nil {
		t.Fatal(err)
	}
	old, err := audit.Open(paths.Audit(auditTestLookup), s, legacyDEK)
	if err != nil {
		t.Fatal(err)
	}
	logOne(t, old)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	lkr.Zero()

	l, cleanup, err := openAuditLogger()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	logOne(t, l)
	sum, err := l.Summarize(audit.SummaryOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalEvents != 2 {
		t.Fatalf("summary saw %d events, want 2 (one sealed with the legacy keyring)", sum.TotalEvents)
	}
	if report := verifyAuditLog(t); report.TotalLines != 2 {
		t.Fatalf("verified %d lines, want 2", report.TotalLines)
	}
}
