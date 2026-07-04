package cli

import (
	"os"

	"github.com/keylatch/keylatch/internal/runtime"
)

// IsExperimentalEnabled reports whether the user has opted into experimental features.
// Two conditions enable experimental mode:
//  1. KEYLATCH_EXPERIMENTAL=1 is set in the process environment (per-process override).
//  2. settings.ExperimentalGated is true (persisted via custom mode config).
//
// The env var takes precedence as a conventional escape hatch; it wins even when
// settings.ExperimentalGated is false. Either condition alone is sufficient.
func IsExperimentalEnabled(settings runtime.EffectiveSettings) bool {
	return os.Getenv("KEYLATCH_EXPERIMENTAL") == "1" || settings.ExperimentalGated
}

// isExperimentalEnabled is a startup-time shim used before EffectiveSettings is resolved.
// It checks only the env var — custom.experimental_gated is NOT consulted here because
// config is not yet loaded at command-tree construction time. Users relying solely on
// custom mode config (without setting KEYLATCH_EXPERIMENTAL=1) will not see experimental
// commands in the tree until this shim is replaced with settings-aware construction.
func isExperimentalEnabled() bool {
	return IsExperimentalEnabled(runtime.EffectiveSettings{})
}

// experimentalCmd describes a single gated command for the `keylatch experimental` listing.
type experimentalCmd struct {
	name string
}

// experimentalCmds is the canonical ordered list of gated commands.
//
// proxy, sandbox, call, broker, approve, and deny have all graduated to
// top-level production commands and are no longer listed here.
var experimentalCmds = []experimentalCmd{}
