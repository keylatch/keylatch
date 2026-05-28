package config_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- OPConfig.Validate tests ---

func TestOPConfig_Validate_EmptyVaultDefaults(t *testing.T) {
	c := &config.OPConfig{Vault: ""}
	require.NoError(t, c.Validate())
	assert.Equal(t, "Keylatch", c.Vault, "empty vault must default to 'Keylatch'")
}

func TestOPConfig_Validate_NonEmptyVaultPreserved(t *testing.T) {
	c := &config.OPConfig{Vault: "Personal"}
	require.NoError(t, c.Validate())
	assert.Equal(t, "Personal", c.Vault, "non-empty vault must be preserved")
}

func TestOPConfig_Validate_AbsoluteBinOK(t *testing.T) {
	c := &config.OPConfig{Bin: "/usr/local/bin/op"}
	require.NoError(t, c.Validate())
}

func TestOPConfig_Validate_RelativeBinRejected(t *testing.T) {
	c := &config.OPConfig{Bin: "op"}
	err := c.Validate()
	require.Error(t, err, "relative bin path must be rejected")
	assert.Contains(t, err.Error(), "absolute path")
}

func TestOPConfig_Validate_EmptyBinOK(t *testing.T) {
	c := &config.OPConfig{Bin: ""}
	require.NoError(t, c.Validate(), "empty bin (PATH lookup) must be allowed")
}

func TestOPConfig_Validate_TeamModeFieldsPassThrough(t *testing.T) {
	// Forward-compat: team-mode fields are stored but not interpreted.
	c := &config.OPConfig{
		ServiceAccountTokenRef: "ref://some-vault/token",
		OrgCollection:          "my-org",
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, "ref://some-vault/token", c.ServiceAccountTokenRef)
	assert.Equal(t, "my-org", c.OrgCollection)
}

// --- BWConfig.Validate tests ---

func TestBWConfig_Validate_HTTPSServerOK(t *testing.T) {
	c := &config.BWConfig{Server: "https://vaultwarden.example.com"}
	require.NoError(t, c.Validate())
}

func TestBWConfig_Validate_HTTPServerRejected(t *testing.T) {
	c := &config.BWConfig{Server: "http://vaultwarden.internal"}
	err := c.Validate()
	require.Error(t, err, "http:// server must be rejected")
	assert.Contains(t, err.Error(), "https://")
}

func TestBWConfig_Validate_EmptyServerOK(t *testing.T) {
	c := &config.BWConfig{Server: ""}
	require.NoError(t, c.Validate(), "empty server (Bitwarden Cloud) must be allowed")
}

func TestBWConfig_Validate_MutualExclusion_FolderAndCollection(t *testing.T) {
	c := &config.BWConfig{Folder: "my-folder", Collection: "my-collection"}
	err := c.Validate()
	require.Error(t, err, "folder+collection must be mutually exclusive")
	var me config.ErrBWMutualExclusion
	assert.True(t, errors.As(err, &me), "error must be ErrBWMutualExclusion")
}

func TestBWConfig_Validate_OnlyFolder_OK(t *testing.T) {
	c := &config.BWConfig{Folder: "my-folder"}
	require.NoError(t, c.Validate())
}

func TestBWConfig_Validate_OnlyCollection_OK(t *testing.T) {
	c := &config.BWConfig{Collection: "my-collection"}
	require.NoError(t, c.Validate())
}

func TestBWConfig_Validate_TeamModeFieldsPassThrough(t *testing.T) {
	c := &config.BWConfig{
		ServiceAccountTokenRef: "ref://some-vault/token",
		OrgCollection:          "my-org",
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, "ref://some-vault/token", c.ServiceAccountTokenRef)
}
