// Package actor derives and validates keylatch actor identities.
// Priority order for Infer:
//  1. env("KEYLATCH_ACTOR") — explicit override (Source="env")
//  2. any variable of a harness in internal/harness, current or legacy → the
//     harness ID, e.g. "claude-code" or "codex" (Source="infer")
//  3. a manual agent label → "llm-session" (Source="infer")
//  4. stdin is a terminal → "human-shell" (Source="infer")
//  5. fallback → "unknown-non-tty" (Source="infer")
//
// Infer never returns an empty Name.
package actor

import (
	"fmt"
	"os"
	"regexp"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"golang.org/x/term"
)

// Actor is a labelled identity with a provenance source.
type Actor struct {
	Name   string `json:"name"`
	Source string `json:"source"` // "infer" | "flag" | "env"
}

// actorNameRe validates actor names: lowercase alphanumeric, hyphens, 1–63 chars.
var actorNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate returns an error if name does not match ^[a-z0-9][a-z0-9-]{0,62}$.
func Validate(name string) error {
	if !actorNameRe.MatchString(name) {
		return fmt.Errorf("actor name %q is invalid: must match ^[a-z0-9][a-z0-9-]{0,62}$", name)
	}
	return nil
}

func anyFires(env llmcontext.Lookup, signals []harness.EnvSignal) bool {
	for _, s := range signals {
		if s.Match.Fires(env(s.Name)) {
			return true
		}
	}
	return false
}

// Infer derives a conservative actor label from the environment.
// It never returns an empty Name.
func Infer(env llmcontext.Lookup) Actor {
	// Priority 1: explicit override.
	if v := env("KEYLATCH_ACTOR"); v != "" {
		return Actor{Name: v, Source: "env"}
	}
	for _, d := range harness.All() {
		if anyFires(env, d.Env) || anyFires(env, d.LegacyEnv) {
			return Actor{Name: d.ID, Source: "infer"}
		}
	}
	if anyFires(env, harness.ManualSignals) {
		return Actor{Name: "llm-session", Source: "infer"}
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return Actor{Name: "human-shell", Source: "infer"}
	}
	// Fallback.
	return Actor{Name: "unknown-non-tty", Source: "infer"}
}
