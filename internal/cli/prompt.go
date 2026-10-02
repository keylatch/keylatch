package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// promptHiddenFn reads one hidden (no-echo) value from the terminal.
// Declared as a var — like stdinScannerFn in setup_cmd.go — so tests can
// replace it with a canned response. Unlike stdinScannerFn, this cannot be
// redirected to a pipe/bytes.Buffer instead: term.ReadPassword's no-echo
// behavior is implemented via raw-mode ioctls on a real terminal fd, so
// there is no io.Reader-level seam to substitute. Tests inject here instead,
// which exercises every real call site's surrounding logic (error handling,
// zeroing, downstream Unlock/Set calls) without needing a real TTY/pty.
var promptHiddenFn = func() ([]byte, error) {
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return value, nil
}

// promptHidden prompts the user for a hidden (password-style) value on stderr,
// reads from the terminal fd directly, and returns the trimmed value.
// If the terminal is not available, returns an error.
func promptHidden(label string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := promptHiddenFn()
	fmt.Fprintln(os.Stderr) // newline after hidden input
	return value, err
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
