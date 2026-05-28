package doctor

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	klruntime "github.com/keylatch/keylatch/internal/runtime"
)

// checkOperatingMode reports the active operating mode and its effective settings.
// EPIC-17: D2 check — satisfies the doctor D-category operating-mode requirement.
func checkOperatingMode(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = config.Default()
		}

		// Resolve the effective mode using the same precedence as runtime (no --mode
		// flag in doctor context, so flag arg is empty).
		resolved, resolveErr := klruntime.ResolveMode("", klruntime.OperatingMode(cfg.Mode))
		if resolveErr != nil {
			return Status{
				Name:    "mode.operating",
				Section: "environment",
				OK:      false,
				Detail:  fmt.Sprintf("invalid operating mode in config: %v", resolveErr),
				Fix:     "Run: keylatch config set mode standard",
				Tags:    []string{"mode"},
			}
		}

		// Map config.CustomModeConfig → runtime.CustomModeConfig if present.
		var customCfg *klruntime.CustomModeConfig
		if cfg.Custom != nil {
			customCfg = &klruntime.CustomModeConfig{
				TelemetryEnabled:       cfg.Custom.TelemetryEnabled,
				CanaryInjectionEnabled: cfg.Custom.CanaryInjectionEnabled,
				ExperimentalGated:      cfg.Custom.ExperimentalGated,
			}
		}

		settings := klruntime.EffectiveSettingsForMode(resolved, customCfg)

		detail := fmt.Sprintf(
			"active=%s, telemetry=%s, canary_injection=%s, experimental_gated=%s",
			resolved,
			boolOnOff(settings.TelemetryEnabled),
			boolOnOff(settings.CanaryInjectionEnabled),
			boolOnOff(settings.ExperimentalGated),
		)

		return Status{
			Name:    "mode.operating",
			Section: "environment",
			OK:      true,
			Detail:  detail,
			Tags:    []string{"mode"},
		}
	}
}

// boolOnOff converts a bool to "on" or "off" for human-readable detail strings.
func boolOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
