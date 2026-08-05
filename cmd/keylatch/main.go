package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
)

func main() {
	root := cli.NewRootCommand()
	if err := root.Execute(); err != nil {
		// §2.5/C5: root.SilenceErrors=true means cobra never prints anything
		// on its own — print the error before the doctor hint so the user
		// sees WHAT failed, not just the generic hint.
		//
		// Most RunE handlers already write their own "Error: ..." message to
		// stderr before returning a plain error; printing err.Error() again
		// here would duplicate it. We only print for error classes that are
		// guaranteed NOT already printed by a handler:
		//   - *cli.CLIError returned directly from a RunE (no call site
		//     prints before `return NewXxxError(...)` — verified: every
		//     manual print site calls os.Exit directly instead of
		//     returning, so it never reaches here).
		//   - cobra/pflag-generated errors (unknown command, wrong arg
		//     count, bad/missing flags) — these never reach any RunE
		//     handler at all, so nothing has printed them yet.
		var cliErr *cli.CLIError
		switch {
		case errors.As(err, &cliErr):
			fmt.Fprint(os.Stderr, cliErr.Stderr())
		case cli.IsCobraGeneratedError(err):
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		}

		// Print doctor hint to stderr before exiting.
		// isDoctorHintSuppressed is not exported; check command name heuristically.
		cmd, _, _ := root.Find(os.Args[1:])
		if cmd != nil && !cli.IsDoctorHintSuppressed(cmd) {
			fmt.Fprintln(os.Stderr, cli.DoctorHint)
		}
		// If the command returned a CLIError, use its specific exit code
		// so that approve/deny and other commands exit with the correct code.
		if errors.As(err, &cliErr) {
			os.Exit(cliErr.Code)
		}
		os.Exit(exitcode.UserError)
	}
}
