package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/testutil"
)

var errAuditOpen = errors.New("keyring missing")

func withAuditUnavailable(t *testing.T) {
	t.Helper()
	prev := openAuditLoggerFn
	openAuditLoggerFn = func() (*audit.Logger, func(), error) { return nil, nil, errAuditOpen }
	t.Cleanup(func() { openAuditLoggerFn = prev })
}

func requireAuditRefusal(t *testing.T, err error) {
	t.Helper()
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != exitcode.SecurityBlock {
		t.Fatalf("error = %v, want a SecurityBlock CLIError", err)
	}
	if !strings.Contains(cliErr.Message, "audit log cannot be opened") || !strings.Contains(cliErr.Message, errAuditOpen.Error()) {
		t.Fatalf("message %q does not explain the missing audit log", cliErr.Message)
	}
}

func TestGatewayUpRefusesWithoutAuditLog(t *testing.T) {
	cfg, _ := fileVaultEnv(t)
	cfgDir := testutil.SetupHermeticConfig(t)
	t.Setenv("KEYLATCH_DATA_DIR", cfg.DataDir)
	withAuditUnavailable(t)

	keyPath := filepath.Join(cfgDir, "gateway", "signing.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freeLoopbackAddr(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	cmd := newGatewayUpCmd()
	cmd.SetArgs([]string{"--port", port})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	requireAuditRefusal(t, cmd.Execute())

	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatal("gateway is listening although the audit log could not be opened")
	}
}

func TestSetRefusesWithoutAuditLog(t *testing.T) {
	cfg, _ := fileVaultEnv(t)
	t.Setenv("KEYLATCH_DATA_DIR", cfg.DataDir)
	withAuditUnavailable(t)
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) { return []byte("new-secret-value"), nil }
	t.Cleanup(func() { promptHiddenFn = prev })

	root := NewRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"set", "default/ai/openrouter/api_key"})
	requireAuditRefusal(t, root.ExecuteContext(context.Background()))
}

func TestListRawRefusesWithoutAuditLog(t *testing.T) {
	cfg, _ := fileVaultEnv(t)
	t.Setenv("KEYLATCH_DATA_DIR", cfg.DataDir)
	testutil.ClearLLMSessionEnv(t)
	withAuditUnavailable(t)
	dispatch.ClearCached()

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"list", "--raw"})
	requireAuditRefusal(t, root.ExecuteContext(context.Background()))
	if out.Len() != 0 {
		t.Fatalf("list --raw printed vault paths without audit: %q", out.String())
	}
}

func TestAuditRefusalNamesUnsafeDirectoryFix(t *testing.T) {
	prev := openAuditLoggerFn
	openAuditLoggerFn = func() (*audit.Logger, func(), error) {
		return nil, nil, fmt.Errorf("audit: open: %w", &audit.UnsafeDirError{Dir: "/tmp/kl", Mode: 0o755})
	}
	t.Cleanup(func() { openAuditLoggerFn = prev })

	_, _, err := requireAuditLogger("set")
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != exitcode.SecurityBlock {
		t.Fatalf("error = %v, want a SecurityBlock CLIError", err)
	}
	if !strings.Contains(cliErr.Message, "chmod 0700 /tmp/kl") {
		t.Fatalf("message %q does not name the permission fix", cliErr.Message)
	}
}
