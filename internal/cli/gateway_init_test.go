package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- M1: gateway init preserves existing custom values ---

func TestGatewayInit_PreservesCustomBindAndMode(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	root := NewRootCommand()
	var out1 bytes.Buffer
	root.SetOut(&out1)
	root.SetErr(&out1)
	root.SetArgs([]string{"gateway", "init"})
	require.NoError(t, root.Execute())

	cfgPath := filepath.Join(configDir, "gateway", "config.json")
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &cfg))

	// Simulate an operator customising bind/mode by hand.
	cfg["bind"] = "0.0.0.0:9999"
	cfg["mode"] = "docker"
	newData, marshalErr := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(cfgPath, newData, 0o600))

	root2 := NewRootCommand()
	var out2 bytes.Buffer
	root2.SetOut(&out2)
	root2.SetErr(&out2)
	root2.SetArgs([]string{"gateway", "init"})
	require.NoError(t, root2.Execute())

	require.Contains(t, out2.String(), "kept existing values")
	require.Contains(t, out2.String(), "bind")
	require.Contains(t, out2.String(), "mode")

	finalData, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var finalCfg map[string]interface{}
	require.NoError(t, json.Unmarshal(finalData, &finalCfg))
	require.Equal(t, "0.0.0.0:9999", finalCfg["bind"])
	require.Equal(t, "docker", finalCfg["mode"])
}

func TestGatewayInit_FillsMissingFieldsOnly(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)

	gatewayDir := filepath.Join(configDir, "gateway")
	require.NoError(t, os.MkdirAll(gatewayDir, 0o700))
	cfgPath := filepath.Join(gatewayDir, "config.json")
	// Only "bind" is set; "mode" is missing and must be filled.
	require.NoError(t, os.WriteFile(cfgPath, []byte(`{"bind":"127.0.0.1:1234"}`), 0o600))

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"gateway", "init"})
	require.NoError(t, root.Execute())

	require.Contains(t, out.String(), "kept existing values: bind")
	require.Contains(t, out.String(), "filled missing fields with defaults: mode")

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &cfg))
	require.Equal(t, "127.0.0.1:1234", cfg["bind"], "existing bind must survive")
	require.Equal(t, "local_process", cfg["mode"], "missing mode must be filled with default")
}
