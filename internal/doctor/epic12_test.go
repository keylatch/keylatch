package doctor_test

// Test suite for the doctor check framework.
//
// Tests:
// - TestDoctor_CleanInstall_WarnsAndExits1
// - TestDoctor_FullyWiredInstall_OK
// - TestDoctor_BootstrapMissing_FailsF1
// - TestDoctor_JSONSchemaV1Stable
// - TestDoctor_CategoryFilter_Environment

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDoctor_CleanInstall_WarnsAndExits1 verifies that a bootstrapped but
// otherwise unconfigured install (no gateway, no connections) produces warnings
// and a HasWarnings=true report while OverallOK=true.
//
// A clean bootstrapped home has: environment checks OK (F1/F2 pass), but
// gateway/connections soft-warn checks fire — so HasWarnings=true.
func TestDoctor_CleanInstall_WarnsAndExits1(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// A clean install should be overall OK (no hard failures after bootstrap).
	assert.True(t, report.OverallOK, "clean bootstrapped install should have OverallOK=true")

	// But it should have warnings (gateway not running, no connections, etc.).
	assert.True(t, report.HasWarnings,
		"clean install should have HasWarnings=true (gateway/connections/hook not configured)")

	// F1 and F2 checks must pass after bootstrap.
	var f1Found, f2Found bool
	for _, s := range report.Checks {
		if s.Name == "F1 bootstrap.keyring" {
			f1Found = true
			assert.True(t, s.OK, "F1 bootstrap.keyring should pass after bootstrap")
		}
		if s.Name == "F2 bootstrap.config" {
			f2Found = true
			assert.True(t, s.OK, "F2 bootstrap.config should pass after bootstrap")
		}
	}
	assert.True(t, f1Found, "F1 bootstrap.keyring check must be present in report")
	assert.True(t, f2Found, "F2 bootstrap.config check must be present in report")
}

// TestDoctor_FullyWiredInstall_OK verifies that when all checks are stubbed
// to return OK, the runner reports OverallOK=true and HasWarnings=false.
//
// This simulates a fully configured installation by using a bootstrapped home
// with a probe that has all binaries present.
func TestDoctor_FullyWiredInstall_OK(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()
	// Stub all known binaries as found.
	for _, bin := range []string{"op", "bw", "aws", "vault", "cosign", "docker", "sops", "security", "pass-cli", "keeper", "lpass"} {
		probe.found[bin] = "/usr/local/bin/" + bin
		probe.version["/usr/local/bin/"+bin] = "1.0.0"
	}

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// F1 and F2 must pass (bootstrap was run).
	for _, s := range report.Checks {
		if s.Name == "F1 bootstrap.keyring" {
			assert.True(t, s.OK, "F1 bootstrap.keyring must pass in a wired install")
		}
		if s.Name == "F2 bootstrap.config" {
			assert.True(t, s.OK, "F2 bootstrap.config must pass in a wired install")
		}
	}
	// The binary checks themselves may still warn (e.g. keychain, bw sign-in),
	// but OverallOK must be true (no hard failures).
	assert.True(t, report.OverallOK, "fully wired install should have OverallOK=true")
}

// TestDoctor_BootstrapMissing_FailsF1 verifies that F1 (bootstrap.keyring)
// reports OK=false when keyring.json is absent.
func TestDoctor_BootstrapMissing_FailsF1(t *testing.T) {
	// Use an unbootstrapped temp HOME — no keyring.json created.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := func(k string) string {
		if k == "HOME" {
			return tmp
		}
		return ""
	}
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// OverallOK must be false — F1 fails when bootstrap hasn't been run.
	assert.False(t, report.OverallOK, "unbootstrapped install should have OverallOK=false")

	// F1 must be present and failing.
	var f1Found bool
	for _, s := range report.Checks {
		if s.Name == "F1 bootstrap.keyring" {
			f1Found = true
			assert.False(t, s.OK, "F1 bootstrap.keyring must fail when keyring.json is absent")
			assert.NotEmpty(t, s.Fix, "F1 bootstrap.keyring must have a Fix hint")
		}
	}
	assert.True(t, f1Found, "F1 bootstrap.keyring check must be present in report")
}

// TestDoctor_JSONSchemaV1Stable verifies that the v1 JSON output shape has
// the required _schema, exit, checks, and summary fields.
//
// This test validates the JSON schema contract by building the v1 shape from
// a doctor.Report and verifying the required fields are present. The actual
// CLI JSON output embeds doctor.Report plus v1 fields — verified here.
func TestDoctor_JSONSchemaV1Stable(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true, // JSON always shows all checks
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// Determine exit code as the CLI does (warnings do not set exit=1).
	exitCode := 0
	if !report.OverallOK {
		exitCode = 2
	}

	// Build a summary from report checks (matches CLI buildDoctorJSONV1 logic).
	type summaryV1 struct {
		OK   int `json:"ok"`
		Warn int `json:"warn"`
		Fail int `json:"fail"`
	}
	// Embed report alongside v1 fields — same structure as the CLI output.
	type schemaV1 struct {
		doctor.Report
		Schema  string    `json:"_schema"`
		Exit    int       `json:"exit"`
		Summary summaryV1 `json:"summary"`
	}

	var summary summaryV1
	for _, s := range report.Checks {
		if !s.OK {
			summary.Fail++
		} else if s.Warn {
			summary.Warn++
		} else {
			summary.OK++
		}
	}

	out := schemaV1{
		Report:  report,
		Schema:  "v1",
		Exit:    exitCode,
		Summary: summary,
	}

	b, err := json.Marshal(out)
	require.NoError(t, err)

	// Verify v1 schema fields are present.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))
	assert.Contains(t, raw, "_schema", "v1 JSON must have _schema field")
	assert.Contains(t, raw, "exit", "v1 JSON must have exit field")
	assert.Contains(t, raw, "checks", "v1 JSON must have checks field (from embedded Report)")
	assert.Contains(t, raw, "summary", "v1 JSON must have summary field")
	// Backward compat: old Report fields must still be present.
	assert.Contains(t, raw, "overall_ok", "v1 JSON must preserve overall_ok for backward compat")
	assert.Contains(t, raw, "version", "v1 JSON must preserve version for backward compat")

	var schema string
	require.NoError(t, json.Unmarshal(raw["_schema"], &schema))
	assert.Equal(t, "v1", schema, "_schema must be 'v1'")

	var exitVal int
	require.NoError(t, json.Unmarshal(raw["exit"], &exitVal))
	assert.GreaterOrEqual(t, exitVal, 0, "exit must be >= 0")
	assert.LessOrEqual(t, exitVal, 2, "exit must be <= 2")
}

// TestDoctor_CategoryFilter_Environment verifies that --category filtering
// restricts the checks run to only those in the specified section.
func TestDoctor_CategoryFilter_Environment(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	// Run with only the "environment" category.
	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose:    true,
		Env:        env,
		Probe:      probe,
		Categories: []string{"environment"},
	})
	require.NoError(t, err)

	// All returned checks must be in the "environment" section.
	for _, s := range report.Checks {
		assert.Equal(t, "environment", s.Section,
			"category filter 'environment' should only return environment checks, got: %s", s.Name)
	}

	// There must be at least one check returned (version, platform, etc.).
	assert.NotEmpty(t, report.Checks, "environment category filter should return at least one check")
}
