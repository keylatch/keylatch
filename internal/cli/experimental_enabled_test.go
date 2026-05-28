package cli_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
)

// TestExperimentalGating_EnvVarOverridesEverything asserts that setting
// KEYLATCH_EXPERIMENTAL=1 enables experimental mode regardless of the
// EffectiveSettings value.
func TestExperimentalGating_EnvVarOverridesEverything(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")

	// Even with ExperimentalGated=false in settings, env var wins.
	settings := runtime.EffectiveSettings{ExperimentalGated: false}
	assert.True(t, cli.IsExperimentalEnabled(settings),
		"KEYLATCH_EXPERIMENTAL=1 must enable experimental mode regardless of EffectiveSettings")
}

// TestExperimentalGating_CustomModeFlagEnables asserts that custom mode with
// ExperimentalGated=true enables experimental mode even without the env var.
func TestExperimentalGating_CustomModeFlagEnables(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")

	settings := runtime.EffectiveSettings{ExperimentalGated: true}
	assert.True(t, cli.IsExperimentalEnabled(settings),
		"ExperimentalGated=true in EffectiveSettings must enable experimental mode without KEYLATCH_EXPERIMENTAL")
}

// TestExperimentalGating_StandardModeDisables asserts that standard mode with
// no env var and ExperimentalGated=false disables experimental mode.
func TestExperimentalGating_StandardModeDisables(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")

	settings := runtime.EffectiveSettings{ExperimentalGated: false}
	assert.False(t, cli.IsExperimentalEnabled(settings),
		"experimental mode must be disabled when KEYLATCH_EXPERIMENTAL is unset and ExperimentalGated=false")
}

// TestExperimentalGating_BothEnvAndFlagEnable asserts that having both the env
// var set and ExperimentalGated=true still returns true (union, not XOR).
func TestExperimentalGating_BothEnvAndFlagEnable(t *testing.T) {
	t.Setenv("KEYLATCH_EXPERIMENTAL", "1")

	settings := runtime.EffectiveSettings{ExperimentalGated: true}
	assert.True(t, cli.IsExperimentalEnabled(settings),
		"experimental mode must be enabled when both env var and ExperimentalGated are set")
}
