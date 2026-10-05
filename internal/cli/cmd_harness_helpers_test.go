package cli

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/spf13/cobra"
)

// cdIsolate points every keylatch path at a fresh temp dir and clears agent
// session signals so commands take their human-terminal code paths.
func cdIsolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	for _, k := range []string{
		"KEYLATCH_CONFIG", "KEYLATCH_POLICY_PATH", "KEYLATCH_GRANTS_PATH", "KEYLATCH_GRANTS_DIR",
		"KEYLATCH_GRANT_ACCESSOR_KEY_PATH", "KEYLATCH_ACTORS_PATH", "KEYLATCH_APPROVALS_DIR",
		"KEYLATCH_GATEWAY_RULES", "KEYLATCH_GATEWAY_PID", "KEYLATCH_VAULT_PATH", "KEYLATCH_ACTOR",
		"KEYLATCH_OP_BIN", "KEYLATCH_OP_VAULT", "KEYLATCH_BW_BIN", "KEYLATCH_BW_SERVER",
		"KEYLATCH_BW_FOLDER", "KEYLATCH_BW_COLLECTION", "BW_SESSION",
	} {
		t.Setenv(k, "")
	}
	testutil.ClearLLMSessionEnv(t)
	return dir
}

type cdResult struct {
	out string
	err string
	e   error
}

// cdExec runs cmd with args and captures stdout/stderr. stdin may be nil.
func cdExec(t *testing.T, cmd *cobra.Command, stdin io.Reader, args ...string) cdResult {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if stdin != nil {
		cmd.SetIn(stdin)
	} else {
		cmd.SetIn(bytes.NewReader(nil))
	}
	cmd.SetArgs(args)
	e := cmd.ExecuteContext(context.Background())
	return cdResult{out: out.String(), err: errOut.String(), e: e}
}

// cdWithJSONRoot nests sub under a parent carrying the global --json flag, the
// way the real root command does.
func cdWithJSONRoot(sub *cobra.Command) *cobra.Command {
	root := &cobra.Command{Use: "keylatch", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().Bool("json", false, "")
	root.AddCommand(sub)
	return root
}
