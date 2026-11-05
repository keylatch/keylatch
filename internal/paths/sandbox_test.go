package paths

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSandboxReadDeniesIncludesRelocatedSecrets(t *testing.T) {
	dir := t.TempDir()
	values := map[string]string{
		"KEYLATCH_CONFIG_DIR":            filepath.Join(dir, "config"),
		"KEYLATCH_VAULT_PATH":            filepath.Join(dir, "vault"),
		"KEYLATCH_KEYRING_IDENTITY_PATH": filepath.Join(dir, "identity"),
		"KEYLATCH_GATEWAY_SIGNING_KEY":   filepath.Join(dir, "signing"),
		"XDG_RUNTIME_DIR":                filepath.Join(dir, "runtime"),
	}
	got := SandboxReadDenies(func(k string) string { return values[k] })
	for _, key := range []string{"KEYLATCH_CONFIG_DIR", "KEYLATCH_VAULT_PATH", "KEYLATCH_KEYRING_IDENTITY_PATH", "KEYLATCH_GATEWAY_SIGNING_KEY"} {
		assert.Contains(t, got, values[key])
	}
	assert.Contains(t, got, filepath.Join(values["XDG_RUNTIME_DIR"], "bus"))
	assert.Contains(t, got, "~/.keylatch")
	assert.Contains(t, got, "~/.local/share/keyrings")
}
