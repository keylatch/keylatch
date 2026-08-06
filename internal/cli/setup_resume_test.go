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

// setupResumeStdin builds a stdinScannerFn replacement feeding the given
// lines (in order) as terminal-style responses, and installs it for the
// duration of the test (H2 resume scenarios below).
func setupResumeStdin(t *testing.T, lines ...string) {
	t.Helper()
	oldScannerFn := stdinScannerFn
	t.Cleanup(func() {
		stdinScannerFn = oldScannerFn
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	}
}

func setupResumeClearLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CLAUDE_CODE", "CODEX_ENV", "CREDENTIALS_LLM_SESSION", "CURSOR_SESSION", "AIDER_SESSION", "GEMINI_SESSION", "OPENCODE_SESSION"} {
		t.Setenv(k, "")
	}
}

// TestSetupResume_EnterThrough_KeepsConfiguredBackend verifies that
// Enter-through resume (blank answer to "Keep current backend? (Y/n)")
// keeps the configured backend rather than silently switching to the OS
// recommendation (H2a).
func TestSetupResume_EnterThrough_KeepsConfiguredBackend(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	setupResumeClearLLMEnv(t)

	require.NoError(t, config.Save(filepath.Join(configDir, "config.json"), config.Config{
		Version:          1,
		Backend:          "op",
		DefaultNamespace: "default",
	}))

	// storage branch, keep-current Y/n, mode choice, provider pick, open-UI.
	setupResumeStdin(t, "", "", "", "", "")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--no-daemon-start"})

	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), "Keep current backend [op]? (Y/n)")
	require.NotContains(t, stdout.String(), "WARNING: switching backend")

	cfg, err := config.Load(filepath.Join(configDir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, "op", cfg.Backend)
}

// TestSetupResume_Switch_RequiresConfirmation verifies that actively
// choosing a different backend on resume requires a typed "switch"
// confirmation before it is persisted (H2b).
func TestSetupResume_Switch_RequiresConfirmation(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	setupResumeClearLLMEnv(t)

	require.NoError(t, config.Save(filepath.Join(configDir, "config.json"), config.Config{
		Version:          1,
		Backend:          "op",
		DefaultNamespace: "default",
	}))

	// storage branch, decline keep-current, pick "1" (file) from the basic
	// menu, confirm "switch", mode choice, provider pick, open-UI.
	setupResumeStdin(t, "", "n", "1", "switch", "", "", "")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--no-daemon-start"})

	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `WARNING: switching backend from "op" to "file"`)
	require.Contains(t, stdout.String(), "Type \"switch\" to confirm")

	cfg, err := config.Load(filepath.Join(configDir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, "file", cfg.Backend)
}

// TestSetupResume_DeclineSwitch_KeepsOldBackend verifies that declining the
// typed "switch" confirmation keeps the previously configured backend (H2c).
func TestSetupResume_DeclineSwitch_KeepsOldBackend(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	setupResumeClearLLMEnv(t)

	require.NoError(t, config.Save(filepath.Join(configDir, "config.json"), config.Config{
		Version:          1,
		Backend:          "op",
		DefaultNamespace: "default",
	}))

	// storage branch, decline keep-current, pick "1" (file), decline the
	// switch confirmation, mode choice, provider pick, open-UI.
	setupResumeStdin(t, "", "n", "1", "", "", "", "")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--no-daemon-start"})

	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), `WARNING: switching backend from "op" to "file"`)
	require.Contains(t, stdout.String(), `Keeping current backend "op"`)

	cfg, err := config.Load(filepath.Join(configDir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, "op", cfg.Backend)
}
