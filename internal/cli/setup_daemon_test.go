package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestSetupStep3SpawnDaemon_AlreadyRunning verifies that setup's step 3
// checks gateway.IsRunning itself and presents an already-running gateway
// as a success (skip), instead of shelling out to `gateway up --detach` and
// reporting the child's expected refusal as a setup failure (M1).
func TestSetupStep3SpawnDaemon_AlreadyRunning(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	pidPath := paths.GatewayPID(llmcontext.DefaultLookup)
	require.NoError(t, os.MkdirAll(paths.GatewayDir(llmcontext.DefaultLookup), 0o700))
	require.NoError(t, gateway.WritePID(pidPath, os.Getpid()))

	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)

	setupStep3SpawnDaemon(cmd)

	require.Contains(t, stdout.String(), fmt.Sprintf("Gateway already running (pid %d) — skipping", os.Getpid()))
	require.NotContains(t, stdout.String(), "gateway init:")
	require.NotContains(t, stdout.String(), "gateway up:")
}
