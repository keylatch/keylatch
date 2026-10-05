package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/spf13/cobra"
)

// reportedError is returned by a handler that has already written its own
// error message to stderr; only the exit code is left to apply.
type reportedError struct {
	code int
	err  error
}

func (e *reportedError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit %d", e.code)
}

func (e *reportedError) Unwrap() error { return e.err }

// reported marks a failure whose message the handler already printed.
// cause, when non-nil, stays reachable through errors.Is/As.
func reported(code int, cause error) error {
	return &reportedError{code: code, err: cause}
}

// ReportError prints err to stderr exactly once and returns the process
// exit code: 0 for nil, the CLIError or reported code when set, otherwise
// exitcode.UserError. A quiet CLIError prints nothing and keeps its code. args are the command-line arguments without the
// program name, used to decide whether to append the doctor hint.
func ReportError(root *cobra.Command, args []string, err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}

	var cliErr *CLIError
	if errors.As(err, &cliErr) && cliErr.Quiet {
		return cliErr.Code
	}

	code := exitcode.UserError
	var rep *reportedError
	switch {
	case errors.As(err, &cliErr):
		fmt.Fprint(stderr, cliErr.Stderr())
		code = cliErr.Code
	case errors.As(err, &rep):
		code = rep.code
	default:
		fmt.Fprintf(stderr, "Error: %s\n", err.Error())
	}
	if code == 0 {
		code = exitcode.UserError
	}

	if cmd, _, _ := root.Find(args); cmd != nil && !IsDoctorHintSuppressed(cmd) {
		fmt.Fprintln(stderr, DoctorHint)
	}
	return code
}
