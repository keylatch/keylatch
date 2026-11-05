package cli

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
)

func TestAgentSocketProbeDoesNotClaimSandboxProof(t *testing.T) {
	for _, reachable := range []bool{true, false} {
		report := probeAgentSocket(func(string) string { return "" }, func(llmcontext.Lookup) (string, error) {
			if reachable {
				return "/example/control.sock", nil
			}
			return "", errors.New("private error")
		})
		assert.Equal(t, reachable, report.Reachable)
		assert.Equal(t, "current-process", report.Source)
		assert.Equal(t, "unknown", report.Sandbox)
		assert.Equal(t, "unknown", report.RuntimeVersion)
		assert.Equal(t, "unknown", report.Harness)
		assert.NotContains(t, report.Detail, "private error")
	}
}
