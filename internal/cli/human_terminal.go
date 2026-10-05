package cli

// interactiveStdin reports whether stdin is an interactive terminal.
// Replaced in tests.
var interactiveStdin = stdinIsTTY

// requireInteractiveTerminal refuses a human-only command when stdin is not a
// terminal. LLM session detection relies on env vars the caller controls, so
// this holds even when detection misses: agent tool calls run without a TTY.
// The error is returned, not printed: main prints every *CLIError once.
func requireInteractiveTerminal(command, code string) error {
	if interactiveStdin() {
		return nil
	}
	return NewSecurityBlock("%s: requires an interactive terminal. Run this command yourself in a terminal; it cannot be scripted, piped or run by an agent. (%s)", command, code)
}
