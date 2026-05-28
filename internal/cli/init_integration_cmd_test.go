package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectProjectLanguage verifies language detection from project file markers.
func TestDetectProjectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		wantLang projectLang
	}{
		{
			name:     "go.mod present",
			files:    []string{"go.mod"},
			wantLang: langGo,
		},
		{
			name:     "package.json present",
			files:    []string{"package.json"},
			wantLang: langNode,
		},
		{
			name:     "pyproject.toml present",
			files:    []string{"pyproject.toml"},
			wantLang: langPython,
		},
		{
			name:     "requirements.txt present",
			files:    []string{"requirements.txt"},
			wantLang: langPython,
		},
		{
			name:     "setup.py present",
			files:    []string{"setup.py"},
			wantLang: langPython,
		},
		{
			name:     "no markers — defaults to shell",
			files:    []string{},
			wantLang: langShell,
		},
		{
			name:     "go.mod takes priority over package.json",
			files:    []string{"go.mod", "package.json"},
			wantLang: langGo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			for _, f := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(tmp, f), []byte(""), 0o600))
			}
			got := detectProjectLanguage(tmp)
			assert.Equal(t, tt.wantLang, got)
		})
	}
}

// TestIsValidIntegrationAgent verifies the agent allowlist.
func TestIsValidIntegrationAgent(t *testing.T) {
	valid := []string{"claude-code", "gemini", "windsurf", "cursor", "generic"}
	for _, a := range valid {
		assert.True(t, isValidIntegrationAgent(a), "expected %q to be valid", a)
	}

	invalid := []string{"", "unknown", "aider", "copilot", "CURSOR", "Claude-Code"}
	for _, a := range invalid {
		assert.False(t, isValidIntegrationAgent(a), "expected %q to be invalid", a)
	}
}

// TestAgentDocSlug verifies agent → doc slug mapping.
func TestAgentDocSlug(t *testing.T) {
	assert.Equal(t, "claude-code", agentDocSlug("claude-code"))
	assert.Equal(t, "gemini", agentDocSlug("gemini"))
	assert.Equal(t, "windsurf", agentDocSlug("windsurf"))
	assert.Equal(t, "cursor", agentDocSlug("cursor"))
	assert.Equal(t, "generic", agentDocSlug("generic"))
	assert.Equal(t, "generic", agentDocSlug("unknown"))
}

// TestWriteIntegrationConfig verifies that the YAML config is written correctly.
func TestWriteIntegrationConfig(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	err := writeIntegrationConfig(cmd, tmp, "claude-code", langShell)
	require.NoError(t, err)

	cfgPath := filepath.Join(tmp, ".keylatch", "integration.yml")
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "agent: claude-code")
	assert.Contains(t, content, "providers:")
	assert.Contains(t, content, "claude-code.md")
}

// TestWriteIntegrationConfig_Idempotent verifies that re-running does not overwrite.
func TestWriteIntegrationConfig_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	klDir := filepath.Join(tmp, ".keylatch")
	require.NoError(t, os.MkdirAll(klDir, 0o750))
	existing := "agent: existing\n"
	require.NoError(t, os.WriteFile(
		filepath.Join(klDir, "integration.yml"),
		[]byte(existing),
		0o600,
	))

	err := writeIntegrationConfig(cmd, tmp, "cursor", langShell)
	require.NoError(t, err)

	// File should still contain the original content.
	data, err := os.ReadFile(filepath.Join(klDir, "integration.yml"))
	require.NoError(t, err)
	assert.Equal(t, existing, string(data))
}

// TestWriteIntegrationScript_Shell verifies the shell script is written.
func TestWriteIntegrationScript_Shell(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	err := writeIntegrationScript(cmd, tmp, "claude-code", langShell)
	require.NoError(t, err)

	scriptPath := filepath.Join(tmp, "scripts", "keylatch-setup.sh")
	data, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "#!/usr/bin/env bash")
	assert.Contains(t, content, "keylatch bootstrap")
	assert.Contains(t, content, "keylatch connect")
}

// TestWriteIntegrationScript_Python verifies the Python script is written.
func TestWriteIntegrationScript_Python(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	err := writeIntegrationScript(cmd, tmp, "gemini", langPython)
	require.NoError(t, err)

	scriptPath := filepath.Join(tmp, "scripts", "keylatch_setup.py")
	data, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "#!/usr/bin/env python3")
	assert.Contains(t, content, "keylatch")
}

// TestWriteIntegrationScript_Node verifies the TypeScript script is written.
func TestWriteIntegrationScript_Node(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	err := writeIntegrationScript(cmd, tmp, "cursor", langNode)
	require.NoError(t, err)

	scriptPath := filepath.Join(tmp, "scripts", "keylatchSetup.ts")
	data, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "keylatch")
	assert.Contains(t, content, "execSync")
}

// TestWriteIntegrationScript_Idempotent verifies script is not overwritten.
func TestWriteIntegrationScript_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	cmd := newInitIntegrationCmd()

	scriptsDir := filepath.Join(tmp, "scripts")
	require.NoError(t, os.MkdirAll(scriptsDir, 0o750))
	existing := "# my existing script\n"
	require.NoError(t, os.WriteFile(
		filepath.Join(scriptsDir, "keylatch-setup.sh"),
		[]byte(existing),
		0o755,
	))

	err := writeIntegrationScript(cmd, tmp, "claude-code", langShell)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(scriptsDir, "keylatch-setup.sh"))
	require.NoError(t, err)
	assert.Equal(t, existing, string(data))
}
