package cli

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGatewayDriversReturnsOnlyGatewayDrivers(t *testing.T) {
	dir := t.TempDir()
	vars := map[string]string{
		"KEYLATCH_GATEWAY_SIGNING_KEY": filepath.Join(dir, "signing.key"),
		"KEYLATCH_GATEWAY_PID":         filepath.Join(dir, "gateway.pid"),
	}
	env := func(k string) string { return vars[k] }

	drivers, err := newGatewayDrivers(env, "")
	require.NoError(t, err)

	keys := make([]string, 0, len(drivers))
	for k := range drivers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"gateway_sdk", "gateway_typed"}, keys)
}

func TestNewGatewayDriversRejectsInvalidGatewayAddr(t *testing.T) {
	env := func(k string) string {
		if k == "KEYLATCH_GATEWAY_ADDR" {
			return "not-a-host-port"
		}
		return ""
	}
	_, err := newGatewayDrivers(env, "")
	assert.Error(t, err)
}
