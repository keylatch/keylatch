package cli_test

// set_cmd_test.go verifies S4-6: secret values must not be passed as positional
// arguments to the set command.

import (
	"bytes"
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/vault"
)

// TestSetCmd_S4_6_RejectsPositionalValue verifies that passing the secret
// value as a positional argument is rejected with a non-zero exit.
// The `set` command uses cobra.ExactArgs(1), so a second positional arg causes
// an argument-count error before RunE is ever called.
func TestSetCmd_S4_6_RejectsPositionalValue(t *testing.T) {
	dir := t.TempDir()
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)
	t.Setenv("KEYLATCH_DATA_DIR", dir)
	t.Setenv("KEYLATCH_BACKEND", "file")

	ctx := context.Background()
	cfg := newTestConfig(dir)
	env := newTestEnv(t, dir)

	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	// Pass a second positional arg (the secret value) — must be rejected.
	root.SetArgs([]string{"set", "openrouter.api_key", "sk-abc"})

	err := root.Execute()
	if err == nil {
		t.Error("expected an error when passing secret value as positional arg (S4-6), got nil")
	}

	// Error message should mention the argument problem (cobra's ExactArgs error).
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("error message must not be empty")
	}

	// The vault must not have been written to.
	// Attempt to read from the vault — it should be empty.
	metas, listErr := vault.ListMeta(ctx, "", cfg, env)
	if listErr != nil {
		// ListMeta returning an error is also acceptable (backend not yet initialised).
		return
	}
	if len(metas) != 0 {
		t.Errorf("S4-6 violated: set command wrote to vault despite positional arg rejection, found %d meta entries", len(metas))
	}
}
