package demo_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/ui/demo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDemoConnections_NotEmpty(t *testing.T) {
	t.Parallel()
	conns := demo.Connections()
	assert.NotEmpty(t, conns)
}

func TestDemoConnections_ValueFree(t *testing.T) {
	t.Parallel()
	conns := demo.Connections()
	for _, c := range conns {
		assert.NotEmpty(t, c.Name)
		assert.NotEmpty(t, c.Provider)
		// No value field should exist.
	}
}

func TestDemoConnections_CanaryFree(t *testing.T) {
	t.Parallel()
	conns := demo.Connections()
	canary.AssertNoLeak(t,
		[]string{canary.Phase10Sentinel},
		canary.JSONResponse(conns),
	)
}

func TestStatusExtra_DemoFlag(t *testing.T) {
	t.Parallel()
	extra := demo.StatusExtra()
	require.Contains(t, extra, "demo")
	assert.Equal(t, true, extra["demo"])
	assert.Contains(t, extra, "demo_banner")
}
