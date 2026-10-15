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
	// A plaintext identity file: these tests open the keyring without a key
	// store, and one of them reads the identity file directly.
	if _, err := bootstrap.Run(context.Background(), bootstrap.Options{Backend: "file", Env: auditTestLookup, InsecureFileKEK: true}); err != nil {
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
	s, err := salt.LoadOrCreate(paths.AuditSalt(auditTestLookup))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := loadAuditKeyMaterial(s, false)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.zero()
	report, err := audit.VerifyChain(paths.Audit(auditTestLookup), keys.seed, keys.dek, keys.older...)
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

	// gateway up opens its audit logger through OpenAuditLogger.
	l, cleanup, err := OpenAuditLogger()
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

// The installed audit log is chained under a key derived from a KEK-wrapped
// secret, so recomputing the chain from the readable audit salt does not
// produce one that verifies; a log written under the old salt-only key is
// moved aside when the secret is first created.
func TestAuditKeyNotFromSaltAlone(t *testing.T) {
	bootstrapForAudit(t)
	s, err := salt.LoadOrCreate(paths.AuditSalt(auditTestLookup))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := paths.Audit(auditTestLookup)

	// A log from before the audit key existed, chained under the salt alone.
	dek := make([]byte, 32)
	legacy, err := audit.Open(auditPath, s, dek)
	if err != nil {
		t.Fatal(err)
	}
	logOne(t, legacy)
	_ = legacy.Close()

	l, cleanup, err := OpenAuditLogger()
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		logOne(t, l)
	}
	cleanup()

	if _, err := os.Stat(auditPath + ".1"); err != nil {
		t.Fatalf("log written under the salt-only key was not retired: %v", err)
	}
	if r := verifyAuditLog(t); r.TotalLines != 3 {
		t.Fatalf("verified %d lines, want 3", r.TotalLines)
	}
	r, err := audit.VerifyChain(auditPath, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.FirstBadLine == 0 {
		t.Fatal("chain verifies under the audit salt alone")
	}
	if _, err := os.Stat(paths.AuditKeyWrapped(auditTestLookup)); err != nil {
		t.Fatalf("wrapped audit key missing: %v", err)
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
	keys, err := loadAuditKeyMaterial(s, true)
	if err != nil {
		t.Fatal(err)
	}
	old, err := audit.Open(paths.Audit(auditTestLookup), keys.seed, legacyDEK)
	if err != nil {
		t.Fatal(err)
	}
	logOne(t, old)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	keys.zero()
	lkr.Zero()

	l, cleanup, err := OpenAuditLogger()
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
