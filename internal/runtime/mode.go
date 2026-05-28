package runtime

import (
	"fmt"
	"os"
	"strings"
)

// OperatingMode identifies the first-class operating posture for a keylatch session.
// It controls which subsystems (telemetry, canary injection, experimental gates) are active.
type OperatingMode string

const (
	ModeStandard  OperatingMode = "standard"
	ModeTelemetry OperatingMode = "telemetry"
	ModeCanary    OperatingMode = "canary"
	ModeCustom    OperatingMode = "custom"
)

// AllOperatingModes is the closed set of valid OperatingMode values.
var AllOperatingModes = []OperatingMode{ModeStandard, ModeTelemetry, ModeCanary, ModeCustom}

// String returns the string representation of the mode.
func (m OperatingMode) String() string { return string(m) }

// ParseMode parses a string into an OperatingMode.
// The comparison is case-insensitive.
func ParseMode(s string) (OperatingMode, error) {
	switch OperatingMode(strings.ToLower(s)) {
	case ModeStandard, ModeTelemetry, ModeCanary, ModeCustom:
		return OperatingMode(strings.ToLower(s)), nil
	default:
		return "", fmt.Errorf("unknown operating mode %q — valid modes: standard, telemetry, canary, custom", s)
	}
}

// ResolveMode applies selection precedence: flag > KEYLATCH_MODE env > cfg > default (standard).
// flagVal is the value of the --mode flag (empty string = not set).
// cfg is the mode stored in config (empty = not set).
func ResolveMode(flagVal string, cfg OperatingMode) (OperatingMode, error) {
	if flagVal != "" {
		return ParseMode(flagVal)
	}
	if envVal := os.Getenv("KEYLATCH_MODE"); envVal != "" {
		return ParseMode(envVal)
	}
	if cfg != "" {
		return ParseMode(string(cfg))
	}
	return ModeStandard, nil
}

// EffectiveSettings is the resolved set of feature flags for an OperatingMode.
type EffectiveSettings struct {
	TelemetryEnabled       bool
	CanaryInjectionEnabled bool
	ExperimentalGated      bool
}

// EffectiveSettingsForMode derives the feature flags for the given mode.
// For ModeCustom, customCfg overrides individual flags; a nil customCfg yields all-false.
func EffectiveSettingsForMode(m OperatingMode, customCfg *CustomModeConfig) EffectiveSettings {
	switch m {
	case ModeTelemetry:
		return EffectiveSettings{TelemetryEnabled: true}
	case ModeCanary:
		return EffectiveSettings{CanaryInjectionEnabled: true}
	case ModeCustom:
		if customCfg != nil {
			return EffectiveSettings{
				TelemetryEnabled:       customCfg.TelemetryEnabled,
				CanaryInjectionEnabled: customCfg.CanaryInjectionEnabled,
				ExperimentalGated:      customCfg.ExperimentalGated,
			}
		}
		return EffectiveSettings{}
	default: // standard
		return EffectiveSettings{}
	}
}

// CustomModeConfig holds the per-feature flags used when OperatingMode is "custom".
// Fields map directly to config yaml keys under the "custom" block.
type CustomModeConfig struct {
	TelemetryEnabled       bool `yaml:"telemetry_enabled"`
	CanaryInjectionEnabled bool `yaml:"canary_injection_enabled"`
	ExperimentalGated      bool `yaml:"experimental_gated"`
}
