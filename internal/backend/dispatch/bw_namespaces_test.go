package dispatch_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The organization and the namespace map in the configuration reach the
// Bitwarden backend, which refuses a namespace it was not given a collection for.
func TestBitwardenNamespacesReachTheBackend(t *testing.T) {
	cfg := config.Default()
	cfg.Backend = "bw"
	cfg.BW = &config.BWConfig{
		Bin:            "/fake/bw",
		OrganizationID: "org-1",
		Namespaces:     map[string]string{"work": "Work/infra"},
	}

	b, err := dispatch.Open(context.Background(), cfg, func(string) string { return "" })
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "personal/ci/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped)
}

func TestBitwardenNamespacesNeedAnOrganization(t *testing.T) {
	cfg := config.Default()
	cfg.Backend = "bw"
	cfg.BW = &config.BWConfig{Bin: "/fake/bw", Namespaces: map[string]string{"work": "Work/infra"}}

	_, err := dispatch.Open(context.Background(), cfg, func(string) string { return "" })
	assert.ErrorContains(t, err, "organization_id")
}
