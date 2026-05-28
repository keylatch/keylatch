// Package actor derives and validates keylatch actor identities.
// Priority order for Infer:
//  1. env("KEYLATCH_ACTOR") — explicit override (Source="env")
//  2. env("CLAUDE_CODE") non-empty → "claude-code" (Source="infer")
//  3. env("CODEX_ENV") non-empty → "codex" (Source="infer")
//  4. env("CREDENTIALS_LLM_SESSION") == "1" → "llm-session" (Source="infer")
//  5. stdin is a terminal → "human-shell" (Source="infer")
//  6. fallback → "unknown-non-tty" (Source="infer")
//
// S8-6: Infer never returns an empty Name.
package actor

import (
	"fmt"
	"os"
	"regexp"

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

// Infer derives a conservative actor label from the environment.
// It never returns an empty Name (S8-6).
func Infer(env llmcontext.Lookup) Actor {
	// Priority 1: explicit override.
	if v := env("KEYLATCH_ACTOR"); v != "" {
		return Actor{Name: v, Source: "env"}
	}
	// Priority 2: Claude Code LLM session.
	if env("CLAUDE_CODE") != "" {
		return Actor{Name: "claude-code", Source: "infer"}
	}
	// Priority 3: Codex session.
	if env("CODEX_ENV") != "" {
		return Actor{Name: "codex", Source: "infer"}
	}
	// Priority 4: generic LLM session signal.
	if env("CREDENTIALS_LLM_SESSION") == "1" {
		return Actor{Name: "llm-session", Source: "infer"}
	}
	// Priority 5: check if stdin is a terminal.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return Actor{Name: "human-shell", Source: "infer"}
	}
	// Fallback.
	return Actor{Name: "unknown-non-tty", Source: "infer"}
}
