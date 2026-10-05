package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runGrantCreate(t *testing.T, args ...string) error {
	t.Helper()
	root := NewRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"grant", "create"}, args...))
	return root.ExecuteContext(context.Background())
}

func grantTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_GRANTS_PATH", filepath.Join(dir, "grants.json"))
	t.Setenv("KEYLATCH_GRANTS_DIR", filepath.Join(dir, "grants"))
	t.Setenv("KEYLATCH_GRANT_ACCESSOR_KEY_PATH", filepath.Join(dir, "grant-accessor.key"))
	testutil.ClearLLMSessionEnv(t)
	return filepath.Join(dir, "grants.json")
}

func requireExitCode(t *testing.T, err error, code int) {
	t.Helper()
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != code {
		t.Fatalf("error = %v, want a CLIError with exit code %d", err, code)
	}
}

func TestGrantCreateRefusedInAgentSession(t *testing.T) {
	grants := grantTestEnv(t)
	withInteractiveStdin(t, true)
	t.Setenv("CLAUDECODE", "1")

	requireExitCode(t, runGrantCreate(t, "prod", "--actor", "claude-code", "--ttl", "1h"), exitcode.SecurityBlock)
	if _, err := os.Stat(grants); !os.IsNotExist(err) {
		t.Fatalf("grant written from an agent session: %v", err)
	}
}

func TestGrantCreateNeedsTerminal(t *testing.T) {
	grants := grantTestEnv(t)
	withInteractiveStdin(t, false)

	requireExitCode(t, runGrantCreate(t, "prod", "--actor", "claude-code"), exitcode.SecurityBlock)
	if _, err := os.Stat(grants); !os.IsNotExist(err) {
		t.Fatalf("grant written without a terminal: %v", err)
	}
}

func TestGrantCreateCapsTTL(t *testing.T) {
	grants := grantTestEnv(t)
	withInteractiveStdin(t, true)

	requireExitCode(t, runGrantCreate(t, "prod", "--actor", "claude-code", "--ttl", "87600h"), exitcode.UserError)
	if _, err := os.Stat(grants); !os.IsNotExist(err) {
		t.Fatalf("grant written with an over-long TTL: %v", err)
	}

	if err := runGrantCreate(t, "prod", "--actor", "claude-code", "--ttl", "2h"); err != nil {
		t.Fatalf("grant create from a human terminal: %v", err)
	}
}
