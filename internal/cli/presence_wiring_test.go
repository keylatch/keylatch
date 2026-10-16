package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runCLI(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), err
}

func presenceTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_GRANTS_PATH", filepath.Join(dir, "grants.json"))
	t.Setenv("KEYLATCH_GRANTS_DIR", filepath.Join(dir, "grants"))
	t.Setenv("KEYLATCH_GRANT_ACCESSOR_KEY_PATH", filepath.Join(dir, "grant-accessor.key"))
	testutil.ClearLLMSessionEnv(t)
	return dir
}

func TestTokenCreateNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	presencetest.NoTerminal(t)

	_, err := runCLI(t, "gateway", "token", "create", "agent", "--allow", "*")
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestTokenCreateSummaryNamesCapabilities(t *testing.T) {
	presenceTestEnv(t)
	seen := presencetest.Record(t)

	// The signing key does not exist, so the command fails after the prompt.
	_, _ = runCLI(t, "gateway", "token", "create", "agent", "--allow", "github.*", "--ttl", "10m")
	if len(*seen) != 1 || !strings.Contains((*seen)[0], "github.*") || !strings.Contains((*seen)[0], "10m0s") {
		t.Fatalf("presence summaries = %q", *seen)
	}
}

func TestTokenCreateWithoutCapabilitiesNeedsNoPresence(t *testing.T) {
	presenceTestEnv(t)
	seen := presencetest.Record(t)

	_, _ = runCLI(t, "gateway", "token", "create", "agent")
	if len(*seen) != 0 {
		t.Fatalf("asked presence for a token with no capabilities: %q", *seen)
	}
}

func TestUIAdminNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	presencetest.NoTerminal(t)

	for _, scope := range []string{"setup", "admin", "token-minting"} {
		_, err := runCLI(t, "ui", "--scope", scope)
		requireExitCode(t, err, exitcode.SecurityBlock)
	}
}

func TestUIDefaultScopeIsRead(t *testing.T) {
	if got := newUICmd().Flag("scope").DefValue; got != "read" {
		t.Fatalf("default scope = %q, want read", got)
	}
}

func TestUIURLNotPrintedWithoutTTY(t *testing.T) {
	presenceTestEnv(t)
	presencetest.Approve(t)
	old := stdoutIsTTY
	stdoutIsTTY = func() bool { return false }
	t.Cleanup(func() { stdoutIsTTY = old })

	out, err := runCLI(t, "ui", "--no-open")
	requireExitCode(t, err, exitcode.SecurityBlock)
	if strings.Contains(out, "http") {
		t.Fatalf("a URL reached non-terminal stdout: %q", out)
	}
}

func TestConfigSetPolicyKeyNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	presencetest.NoTerminal(t)

	for _, key := range []string{"policy.default", "gateway.addr", "backends.file.dir", "guard.mode", "POLICY.x"} {
		_, err := runCLI(t, "config", "set", key, "v")
		requireExitCode(t, err, exitcode.SecurityBlock)
	}
}

func TestGuardUninstallNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	presencetest.NoTerminal(t)

	_, err := runCLI(t, "install-guard", "claude-code", "--uninstall")
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestGrantRevokeNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	presencetest.NoTerminal(t)

	_, err := runCLI(t, "grant", "revoke", "g-1")
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestGrantCreateRecordsPresenceDigest(t *testing.T) {
	grants := grantTestEnv(t)
	withInteractiveStdin(t, true)
	presencetest.Approve(t)

	if err := runGrantCreate(t, "prod", "--actor", "dev", "--ttl", "30m"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(grants)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"presence_digest"`) {
		t.Fatalf("grant carries no presence digest: %s", data)
	}
}

// The refusal for raw-credential exposure must not tell the reader how to
// switch the check off: that reader may be the agent it stops.
func TestRefusalHasNoBypassHint(t *testing.T) {
	err := RequireRawCredentialOptIn(true, false)
	if err == nil {
		t.Fatal("raw credential exposure allowed without operator config")
	}
	for _, hint := range []string{"KEYLATCH_", "ALLOW_UNVERIFIED", "allow_unverified_session", "export "} {
		if strings.Contains(err.Error(), hint) {
			t.Fatalf("refusal names a bypass %q: %v", hint, err)
		}
	}
}

func TestNoEnvOptOutForUnverifiedSession(t *testing.T) {
	t.Setenv("KEYLATCH_ALLOW_UNVERIFIED_SESSION", "1")
	t.Setenv("KEYLATCH_LLM_TICKET", "forged")
	if err := RequireRawCredentialOptIn(true, false); err == nil {
		t.Fatal("an environment variable allowed raw credential exposure")
	}
}

type fixedStore struct{ paths []string }

func (s fixedStore) List(context.Context, string) ([]backend.Entry, error) {
	out := make([]backend.Entry, len(s.paths))
	for i, p := range s.paths {
		out[i] = backend.Entry{Meta: backend.Meta{Path: p}, Exists: true}
	}
	return out, nil
}

func (fixedStore) Get(context.Context, string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, backend.ErrNotFound
}

func withBackupStore(t *testing.T, paths ...string) {
	t.Helper()
	old := backupStore
	backupStore = func(config.Config, llmcontext.Lookup) backupCredStore { return fixedStore{paths: paths} }
	t.Cleanup(func() { backupStore = old })
}

func TestBackupNeedsPresence(t *testing.T) {
	presenceTestEnv(t)
	withBackupStore(t, "default/ai/openai", "default/ai/anthropic")
	presencetest.NoTerminal(t)

	_, err := runCLI(t, "backup", "--output", filepath.Join(t.TempDir(), "b.enc"))
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestBackupSummaryCountsCredentials(t *testing.T) {
	presenceTestEnv(t)
	withBackupStore(t, "default/ai/openai", "default/ai/anthropic", "default/ai/openai/meta")
	seen := presencetest.Record(t)
	withInteractiveStdin(t, false)

	_, err := runCLI(t, "backup", "--output", filepath.Join(t.TempDir(), "b.enc"))
	requireExitCode(t, err, exitcode.SecurityBlock) // stops at the terminal-only passphrase
	if len(*seen) != 1 || !strings.Contains((*seen)[0], "Export 2 connection credential(s)") {
		t.Fatalf("presence summaries = %q", *seen)
	}
}

func TestBackupPassphraseFileRemoved(t *testing.T) {
	presenceTestEnv(t)
	presencetest.Approve(t)

	_, err := runCLI(t, "backup", "--passphrase-file", "/dev/null")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("err = %v, want an unknown-flag usage error", err)
	}
}
