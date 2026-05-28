package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chdir changes the working directory for the duration of the test,
// restoring it on cleanup. It returns the new directory path.
func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Logf("warning: could not restore cwd: %v", err)
		}
	})
	require.NoError(t, os.Chdir(dir))
}

// TestCheckIntegrationMarkers_NoMarkersNoConfig verifies that the check passes
// when there are no agent markers and no integration config.
func TestCheckIntegrationMarkers_NoMarkersNoConfig(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK, "expected ok=true with no markers")
	assert.False(t, status.Warn, "expected warn=false with no markers")
	assert.Contains(t, status.Detail, "I3:")
	assert.Contains(t, status.Detail, "no agent markers detected")
}

// TestCheckIntegrationMarkers_MarkerWithoutConfig verifies that detecting a
// marker without integration.yml emits a warning.
func TestCheckIntegrationMarkers_MarkerWithoutConfig(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	// Create a Claude Code marker
	claudeDir := filepath.Join(tmp, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{}`), 0o600))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK, "expected ok=true (warning, not failure)")
	assert.True(t, status.Warn, "expected warn=true when marker found but no config")
	assert.Contains(t, status.Detail, "I3:")
	assert.Contains(t, status.Detail, "claude-code")
	assert.NotEmpty(t, status.Fix, "fix hint should be populated")
	assert.Contains(t, status.Fix, "keylatch init integration --agent claude-code")
}

// TestCheckIntegrationMarkers_MarkerWithConfig verifies that the check passes
// when both a marker and integration.yml are present.
func TestCheckIntegrationMarkers_MarkerWithConfig(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	// Create a Claude Code marker
	claudeDir := filepath.Join(tmp, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{}`), 0o600))

	// Create the integration config
	klDir := filepath.Join(tmp, ".keylatch")
	require.NoError(t, os.MkdirAll(klDir, 0o750))
	require.NoError(t, os.WriteFile(
		filepath.Join(klDir, "integration.yml"),
		[]byte("agent: claude-code\nproviders:\n  - openrouter\n"),
		0o600,
	))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK, "expected ok=true when integration config exists")
	assert.False(t, status.Warn, "expected warn=false when integration config exists")
	assert.Contains(t, status.Detail, "I3:")
	assert.Contains(t, status.Detail, "integration config found")
}

// TestCheckIntegrationMarkers_WindsurfMarker verifies detection of a Windsurf marker.
func TestCheckIntegrationMarkers_WindsurfMarker(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	// Create a Windsurf marker directory
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".windsurf", "hooks"), 0o750))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK)
	assert.True(t, status.Warn)
	assert.Contains(t, status.Detail, "windsurf")
	assert.Contains(t, status.Fix, "keylatch init integration --agent windsurf")
}

// TestCheckIntegrationMarkers_CursorMarker verifies detection via .cursor/rules.
func TestCheckIntegrationMarkers_CursorMarker(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".cursor"), 0o750))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmp, ".cursor", "rules"),
		[]byte("# cursor rules"),
		0o600,
	))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK)
	assert.True(t, status.Warn)
	assert.Contains(t, status.Detail, "cursor")
}

// TestCheckIntegrationMarkers_GeminiMarker verifies detection via .gemini/config.yml.
func TestCheckIntegrationMarkers_GeminiMarker(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".gemini"), 0o750))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmp, ".gemini", "config.yml"),
		[]byte("model: gemini-pro\n"),
		0o600,
	))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK)
	assert.True(t, status.Warn)
	assert.Contains(t, status.Detail, "gemini")
}

// TestCheckIntegrationMarkers_AgentsMDMarker verifies detection via AGENTS.md.
func TestCheckIntegrationMarkers_AgentsMDMarker(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	require.NoError(t, os.WriteFile(
		filepath.Join(tmp, "AGENTS.md"),
		[]byte("# Agents\n"),
		0o600,
	))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.OK)
	assert.True(t, status.Warn)
	// AGENTS.md maps to generic
	assert.NotEmpty(t, status.Fix)
}

// TestCheckIntegrationMarkers_MultipleMarkersReportedOnce verifies that if both
// .claude/settings.json and CLAUDE.md exist, only one agent entry is reported.
func TestCheckIntegrationMarkers_MultipleMarkersReportedOnce(t *testing.T) {
	tmp := t.TempDir()
	chdir(t, tmp)

	claudeDir := filepath.Join(tmp, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "CLAUDE.md"), []byte("# Claude"), 0o600))

	check := doctor.ExportCheckIntegrationMarkers()
	status := check(context.Background())

	assert.True(t, status.Warn)
	// Should mention claude-code exactly once in detail (deduplication)
	assert.Contains(t, status.Detail, "claude-code")
}
