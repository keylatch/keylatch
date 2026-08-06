package cli

import (
	"bufio"
	"bytes"
	"os"
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

// TestSetupResume_UnreadableConfig_AbortsSetup verifies the review-flagged
// warn-1 gap is fixed: a config file that exists but cannot be read
// (permission denied) must abort setup with a clear error instead of
// silently treating it as "no configured backend" and skipping straight to
// the fresh-install flow (which would bypass H2's switch-confirmation gate
// entirely).
func TestSetupResume_UnreadableConfig_AbortsSetup(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	setupResumeClearLLMEnv(t)

	cfgPath := filepath.Join(configDir, "config.json")
	original := config.Config{Version: 1, Backend: "op", DefaultNamespace: "default"}
	require.NoError(t, config.Save(cfgPath, original))

	if err := os.Chmod(cfgPath, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgPath, 0o600) })
	if _, readErr := os.ReadFile(cfgPath); readErr == nil {
		t.Skip("file is still readable despite chmod 0o000 (likely running as root)")
	}

	// Only the storage-branch prompt should be consumed before setup aborts.
	setupResumeStdin(t, "")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--no-daemon-start"})

	err := root.Execute()
	require.Error(t, err, "setup must abort rather than silently treat an unreadable config as fresh")
	require.Contains(t, err.Error(), cfgPath)

	require.NotContains(t, stdout.String(), "Recommended backend:", "must not fall through to the fresh-install flow")
	require.NotContains(t, stdout.String(), "Configured backend:")

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Empty(t, matches, "an abort must never produce a backup")

	require.NoError(t, os.Chmod(cfgPath, 0o600))
	stillOriginal, readErr := config.Load(cfgPath)
	require.NoError(t, readErr)
	require.Equal(t, original, stillOriginal, "the original config must be completely untouched")
}

// TestSetupResume_UnusableConfig_TreatedAsFreshWithWarning verifies that a
// readable-but-content-unusable config (version mismatch) surfaces the
// same M2 warning before the backend prompt, and is treated as a fresh
// install rather than silently skipping straight past it with no
// indication anything was wrong (warn-1).
func TestSetupResume_UnusableConfig_TreatedAsFreshWithWarning(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	setupResumeClearLLMEnv(t)

	cfgPath := filepath.Join(configDir, "config.json")
	data := `{"version":99,"backend":"op","default_namespace":"work","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"}}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(data), 0o600))

	// storage branch, decline the recommended backend (avoids macOS keychain
	// in CI), pick "1" (file) from the basic menu, mode choice, provider
	// pick, open-UI.
	setupResumeStdin(t, "", "n", "1", "", "", "")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"setup", "--no-daemon-start"})

	require.NoError(t, root.Execute())

	require.Contains(t, stderr.String(), "existing config")
	require.Contains(t, stderr.String(), "is unusable")
	require.Contains(t, stdout.String(), "Recommended backend:", "an unusable config must fall through to the fresh-install flow, not silently vanish")
	require.NotContains(t, stdout.String(), "Keep current backend", "no configured backend was recoverable, so the H2 keep-current prompt must not appear")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "file", cfg.Backend)

	matches, globErr := filepath.Glob(cfgPath + ".bak.*")
	require.NoError(t, globErr)
	require.Len(t, matches, 1, "the unusable config must still be backed up once, when it is actually persisted over")
}

// TestSetupSecurityBlockMessage_NamesTriggeringSignal verifies the LLM
// session guard explains itself with the concrete env var that fired,
// instead of a generic refusal (M8).
func TestSetupSecurityBlockMessage_NamesTriggeringSignal(t *testing.T) {
	env := func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}

	msg := setupSecurityBlockMessage(env)
	require.Contains(t, msg, "must be run interactively")
	require.Contains(t, msg, "CLAUDE_CODE")
	require.Contains(t, msg, "--headless")
}

// TestSetupSecurityBlockMessage_NoEnvSignal covers the case where the block
// came from a stronger signal than an env var (ticket/daemon) — Reasons()
// reports nothing, so the message must not claim a specific env var fired.
func TestSetupSecurityBlockMessage_NoEnvSignal(t *testing.T) {
	env := func(string) string { return "" }

	msg := setupSecurityBlockMessage(env)
	require.Contains(t, msg, "must be run interactively")
	require.Contains(t, msg, "not an environment variable")
	require.Contains(t, msg, "--headless")
}
