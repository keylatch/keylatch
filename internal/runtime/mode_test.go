package runtime_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/runtime"
)

func TestResolveMode_FlagWins(t *testing.T) {
	t.Setenv("KEYLATCH_MODE", "custom")
	got, err := runtime.ResolveMode("canary", runtime.ModeCustom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != runtime.ModeCanary {
		t.Fatalf("expected canary, got %q", got)
	}
}

func TestResolveMode_EnvBeatsCfg(t *testing.T) {
	t.Setenv("KEYLATCH_MODE", "custom")
	got, err := runtime.ResolveMode("", runtime.ModeCanary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != runtime.ModeCustom {
		t.Fatalf("expected custom, got %q", got)
	}
}

func TestResolveMode_CfgBeatsDefault(t *testing.T) {
	os.Unsetenv("KEYLATCH_MODE")
	got, err := runtime.ResolveMode("", runtime.ModeCanary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != runtime.ModeCanary {
		t.Fatalf("expected canary, got %q", got)
	}
}

func TestResolveMode_DefaultIsStandard(t *testing.T) {
	os.Unsetenv("KEYLATCH_MODE")
	got, err := runtime.ResolveMode("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != runtime.ModeStandard {
		t.Fatalf("expected standard, got %q", got)
	}
}

func TestParseMode_RejectsUnknown(t *testing.T) {
	_, err := runtime.ParseMode("bogus")
	if err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestParseMode_CaseInsensitive(t *testing.T) {
	got, err := runtime.ParseMode("CANARY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != runtime.ModeCanary {
		t.Fatalf("expected canary, got %q", got)
	}
}

func TestEffectiveSettings_StandardDisablesCanary(t *testing.T) {
	s := runtime.EffectiveSettingsForMode(runtime.ModeStandard, nil)
	if s.CanaryInjectionEnabled {
		t.Fatal("standard mode must not enable canary injection")
	}
}

func TestEffectiveSettings_CanaryEnablesInjector(t *testing.T) {
	s := runtime.EffectiveSettingsForMode(runtime.ModeCanary, nil)
	if !s.CanaryInjectionEnabled {
		t.Fatal("canary mode must enable canary injection")
	}
}

func TestParseMode_TelemetryRemoved(t *testing.T) {
	if _, err := runtime.ParseMode("telemetry"); err == nil {
		t.Fatal("the telemetry operating mode no longer exists")
	}
}

func TestEffectiveSettings_CustomReadsIndividualKeys(t *testing.T) {
	cfg := &runtime.CustomModeConfig{
		CanaryInjectionEnabled: true,
		ExperimentalGated:      true,
	}
	s := runtime.EffectiveSettingsForMode(runtime.ModeCustom, cfg)
	if !s.CanaryInjectionEnabled {
		t.Fatal("custom: CanaryInjectionEnabled should be true")
	}
	if !s.ExperimentalGated {
		t.Fatal("custom: ExperimentalGated should be true")
	}
}

func TestEffectiveSettings_CustomNilConfig(t *testing.T) {
	s := runtime.EffectiveSettingsForMode(runtime.ModeCustom, nil)
	if s.CanaryInjectionEnabled || s.ExperimentalGated {
		t.Fatal("custom with nil config must produce all-false settings")
	}
}
