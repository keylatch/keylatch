package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateHostPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"valid loopback", "127.0.0.1:7878", false},
		{"valid all-interfaces empty host", ":7878", false},
		{"valid hostname", "localhost:7878", false},
		{"missing port", "127.0.0.1", true},
		{"non-numeric port", "127.0.0.1:abc", true},
		{"port zero", "127.0.0.1:0", true},
		{"port too large", "127.0.0.1:70000", true},
		{"empty string", "", true},
		{"garbage", "not a valid addr!!", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateHostPort(tc.addr)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGatewayRunAddr_ValidatesEnvOverride(t *testing.T) {
	t.Parallel()

	// Default (no override).
	addr, err := gatewayRunAddr(func(string) string { return "" })
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:7878", addr)

	// Valid override.
	addr, err = gatewayRunAddr(func(k string) string {
		if k == "KEYLATCH_GATEWAY_ADDR" {
			return "10.0.0.5:9999"
		}
		return ""
	})
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5:9999", addr)

	// Malformed override — clear error, no fallback.
	_, err = gatewayRunAddr(func(k string) string {
		if k == "KEYLATCH_GATEWAY_ADDR" {
			return "not-valid"
		}
		return ""
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_GATEWAY_ADDR")
}

func TestProxyRunAddr_ValidatesEnvOverride(t *testing.T) {
	t.Parallel()

	addr, err := proxyRunAddr(func(string) string { return "" })
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:7879", addr)

	_, err = proxyRunAddr(func(k string) string {
		if k == "KEYLATCH_PROXY_ADDR" {
			return "bad::addr"
		}
		return ""
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_PROXY_ADDR")
}
