package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
)

// TestGatewayRunning_NotRunning_IsInformationalNotWarn is the regression
// test: the gateway is an optional runtime feature — most installs never
// start it — so "gateway.pid not found" must no longer set Warn (which
// forced doctor's exit code to 1 on every normal install).
func TestGatewayRunning_NotRunning_IsInformationalNotWarn(t *testing.T) {
	tmp := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return tmp
		}
		return ""
	}

	check := doctor.ExportCheckGatewayRunning(env)
	status := check(context.Background())

	assert.Equal(t, "gateway.running", status.Name)
	assert.True(t, status.OK)
	assert.False(t, status.Warn, "gateway-not-running is informational, not a warning")
	assert.Contains(t, status.Detail, "not running")
}

// TestGatewayRunning_StalePID_StillWarns verifies the stale-PID branch (a
// genuine leftover-state problem, not just "the optional feature is off")
// still warns, and that its Name/Tags bug is fixed (was Name="gateway",
// no Tags).
func TestGatewayRunning_StalePID_StillWarns(t *testing.T) {
	tmp := t.TempDir()
	require := func(err error) {
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	require(os.MkdirAll(tmp, 0o755))
	pidPath := filepath.Join(tmp, "gateway.pid")
	// PID 999999999 is astronomically unlikely to be a live process.
	require(os.WriteFile(pidPath, []byte("999999999"), 0o600))

	env := func(k string) string {
		if k == "KEYLATCH_GATEWAY_PID" {
			return pidPath
		}
		return ""
	}

	check := doctor.ExportCheckGatewayRunning(env)
	status := check(context.Background())

	assert.Equal(t, "gateway.running", status.Name, "Name bug fixed (was 'gateway')")
	assert.NotEmpty(t, status.Tags, "Tags bug fixed (was missing)")
	assert.True(t, status.Warn, "a stale PID file is a genuine problem and must still warn")
}

// TestPlaintextRetention_MonitorNotRunning_IsInformationalNotWarn is a
// regression test for the plaintext-retention check: the runtime monitor (`keylatch ui`) is optional —
// most installs never start it.
func TestPlaintextRetention_MonitorNotRunning_IsInformationalNotWarn(t *testing.T) {
	env := func(k string) string {
		if k == "KEYLATCH_UI_ADDR" {
			return "127.0.0.1:1" // nothing listens here
		}
		return ""
	}

	check := doctor.ExportCheckPlaintextRetention(env)
	status := check(context.Background())

	assert.Equal(t, "plaintext_retention", status.Name)
	assert.True(t, status.OK)
	assert.False(t, status.Warn, "monitor-not-running is informational, not a warning")
}

// TestNoConnections_NotConfigured_IsInformationalNotWarn is a
// regression test: no connections configured yet is not a health problem.
func TestNoConnections_NotConfigured_IsInformationalNotWarn(t *testing.T) {
	tmp := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return tmp
		}
		return ""
	}

	check := doctor.ExportCheckNoConnections(env)
	status := check(context.Background())

	assert.Equal(t, "connections.configured", status.Name)
	assert.True(t, status.OK)
	assert.False(t, status.Warn, "no-connections-yet is informational, not a warning")
}
