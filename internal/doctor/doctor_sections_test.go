package doctor_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRun_SectionsPresent verifies that Report.Sections is populated and
// contains the expected section names after a full run.
func TestRun_SectionsPresent(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// We expect at least the environment and backends sections to appear.
	sectionNames := make(map[string]bool, len(report.Sections))
	for _, sec := range report.Sections {
		sectionNames[sec.Name] = true
		assert.Positive(t, sec.CheckCount, "section %q should have at least one check", sec.Name)
	}

	assert.True(t, sectionNames["environment"], "expected 'environment' section in report.Sections")
	assert.True(t, sectionNames["backends"], "expected 'backends' section in report.Sections")
	assert.True(t, sectionNames["daemon"], "expected 'daemon' section in report.Sections")
	assert.True(t, sectionNames["providers"], "expected 'providers' section in report.Sections")
}

// TestRun_SectionSummary_OKField verifies that a section's OK field is false
// when any check in that section fails.
func TestRun_SectionSummary_OKField(t *testing.T) {
	// Unbootstrapped home — paths checks will fail (environment section).
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

	// Find the environment section — it should have OK=false because paths fail.
	for _, sec := range report.Sections {
		if sec.Name == "environment" {
			assert.False(t, sec.OK, "environment section should be OK=false when paths are missing")
			return
		}
	}
	t.Error("environment section not found in report.Sections")
}

// TestRun_HasWarnings verifies that report.HasWarnings is true when at
// least one check has Warn=true (always the case in a fresh bootstrapped home
// due to ACL/connection/gateway checks).
func TestRun_HasWarnings(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// In a bootstrapped home several soft-warn checks fire (gateway, connections, etc.)
	assert.True(t, report.HasWarnings, "bootstrapped home should have HasWarnings=true due to soft-warn checks")
}

// TestRun_StatusHasSection verifies that every Status in Checks has a Section field set.
func TestRun_StatusHasSection(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	for _, s := range report.Checks {
		assert.NotEmpty(t, s.Section, "check %q should have a Section field", s.Name)
	}
}
