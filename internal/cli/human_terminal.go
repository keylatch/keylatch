package cli

import (
	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/spf13/cobra"
)

// interactiveStdin reports whether stdin is an interactive terminal.
// Replaced in tests.
var interactiveStdin = stdinIsTTY

// requireInteractiveTerminal refuses a human-only command when stdin is not a
// terminal. LLM session detection relies on env vars the caller controls, so
// this holds even when detection misses: agent tool calls run without a TTY.
func requireInteractiveTerminal(c *cobra.Command, command, code string) error {
	if interactiveStdin() {
		return nil
	}
	msg := command + ": requires an interactive terminal"
	cmderr.Format(c.ErrOrStderr(), cmderr.Wrap(
		msg,
		nil,
		"Run this command yourself in a terminal. It cannot be scripted, piped or run by an agent.",
		code,
	))
	return NewSecurityBlock("%s", msg)
}
