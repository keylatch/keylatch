//go:build darwin

package sandbox_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadManifest_ValidIDNotFound verifies that a valid (non-traversal) profile ID
// returns an error when the profile file does not exist.
func TestLoadManifest_ValidIDNotFound(t *testing.T) {
	_, err := sandbox.LoadManifest("nonexistent-profile-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read manifest")
}

// TestLoadManifest_ValidProfile_ViaTempHome loads a profile file from a temp
// directory by overriding HOME so that LoadManifest resolves the right path.
func TestLoadManifest_ValidProfile_ViaTempHome(t *testing.T) {
	tempHome := t.TempDir()
	profileDir := filepath.Join(tempHome, ".keylatch", "sandbox-profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o700))

	execContent := []byte("#!/bin/sh\ntrue\n")
	execPath := filepath.Join(tempHome, "myexec")
	require.NoError(t, os.WriteFile(execPath, execContent, 0o755))

	sum := sha256.Sum256(execContent)
	execHash := hex.EncodeToString(sum[:])

	yamlContent := "profile_id: myprofile\nexecutable: " + execPath + "\nexec_hash: " + execHash + "\n"
	manifestPath := filepath.Join(profileDir, "myprofile.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(yamlContent), 0o600))

	// Override HOME so LoadManifest resolves ~/.keylatch inside tempHome.
	t.Setenv("HOME", tempHome)

	m, err := sandbox.LoadManifest("myprofile")
	require.NoError(t, err)
	assert.Equal(t, "myprofile", m.ProfileID)
	assert.Equal(t, execPath, m.Executable)
}

// TestLoadManifest_MalformedYAML verifies that a corrupt manifest file returns a parse error.
func TestLoadManifest_MalformedYAML(t *testing.T) {
	tempHome := t.TempDir()
	profileDir := filepath.Join(tempHome, ".keylatch", "sandbox-profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o700))

	manifestPath := filepath.Join(profileDir, "badprofile.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte("{{{invalid yaml"), 0o600))

	t.Setenv("HOME", tempHome)

	_, err := sandbox.LoadManifest("badprofile")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse manifest")
}
