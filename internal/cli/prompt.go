package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// promptHidden prompts the user for a hidden (password-style) value on stderr,
// reads from the terminal fd directly, and returns the trimmed value.
// If the terminal is not available, returns an error.
func promptHidden(label string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return value, nil
}

// stdinIsTTY returns true when os.Stdin is connected to a terminal.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readFieldFromStdin reads a value from stdin, trimming trailing newlines.
// Used for the --<fieldname>-stdin convenience flag.
func readFieldFromStdin(r io.Reader) ([]byte, error) {
	val, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	return bytes.TrimRight(val, "\r\n"), nil
}
