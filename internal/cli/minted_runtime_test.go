package cli

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateRuntimeFollowsTheTemplate(t *testing.T) {
	require.NoError(t, registry.InitFromConfig(context.Background(), func(string) string { return "" }))
	cases := []struct {
		name string
		args []string
		want runtime.RuntimeMode
	}{
		{"mint-capable template", []string{"github-app", "gh", "api"}, runtime.RuntimeMinted},
		{"template preferring the SDK gateway", []string{"openrouter", "curl"}, runtime.RuntimeGatewaySDK},
		{"template still naming the retired mode", []string{"dropbox", "rclone"}, runtime.RuntimeGatewayTyped},
		{"unknown connection", []string{"no-such-connection", "x"}, runtime.RuntimeGatewayTyped},
		{"no connection", nil, runtime.RuntimeGatewayTyped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, templateRuntime(context.Background(), tc.args))
		})
	}
}
