package cli

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/require"
)

func TestSetupInteractive_ExistingConfigContinuesWizard(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")
	t.Setenv("CURSOR_SESSION", "")
	t.Setenv("AIDER_SESSION", "")
	t.Setenv("GEMINI_SESSION", "")
	t.Setenv("OPENCODE_SESSION", "")

	require.NoError(t, config.Save(filepath.Join(configDir, "config.json"), config.Config{
		Version:          1,
		Backend:          "keychain",
		DefaultNamespace: "default",
	}))

	oldScannerFn := stdinScannerFn
	t.Cleanup(func() {
		stdinScannerFn = oldScannerFn
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader("\n\n\n\n"))
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--backend", "file", "--no-daemon-start"})

	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), "Existing Keylatch config found")
	require.Contains(t, stdout.String(), "[1/5] Detecting platform")
	require.Contains(t, stdout.String(), "[4/5] Connect your first provider")
	require.NotContains(t, stdout.String(), "You're already set up")

	cfg, err := config.Load(filepath.Join(configDir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, "file", cfg.Backend)
}
