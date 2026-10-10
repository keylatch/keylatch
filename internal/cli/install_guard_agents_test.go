package cli_test

// install_guard_agents_test.go tests install-guard for the harnesses that read
// a JSON hooks file, and the Aider launch-only message.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runInstallGuard(t *testing.T, agent string) (string, error) {
	t.Helper()
	root := cli.NewRootCommand()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"install-guard", agent})
	err := root.ExecuteContext(context.Background())
	return outBuf.String(), err
}

func TestInstallGuard_HooksFileAgents(t *testing.T) {
	cases := map[string]string{
		"windsurf":    filepath.Join(".codeium", "windsurf", "hooks.json"),
		"antigravity": filepath.Join(".gemini", "config", "hooks.json"),
		"cursor":      filepath.Join(".cursor", "hooks.json"),
	}
	for agent, rel := range cases {
		t.Run(agent, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)

			out, err := runInstallGuard(t, agent)
			require.NoError(t, err)
			assert.Contains(t, out, filepath.Join(home, rel))

			data, err := os.ReadFile(filepath.Join(home, rel))
			require.NoError(t, err)
			assert.Contains(t, string(data), "--harness "+agent)
			assert.FileExists(t, filepath.Join(home, ".keylatch", "hooks", "block-keylatch-exfiltration.sh"))
		})
	}
}

func TestInstallGuard_AiderIsLaunchOnly(t *testing.T) {
	_, err := runInstallGuard(t, "aider")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no hook API")
	assert.Contains(t, err.Error(), "keylatch launch")
}
