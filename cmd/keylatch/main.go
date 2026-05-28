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
		// §2.5: print the doctor hint on any non-trivial error (not --help/--version/doctor).
		// Print doctor hint to stderr before exiting.
		// isDoctorHintSuppressed is not exported; check command name heuristically.
		cmd, _, _ := root.Find(os.Args[1:])
		if cmd != nil && !cli.IsDoctorHintSuppressed(cmd) {
			fmt.Fprintln(os.Stderr, cli.DoctorHint)
		}
		// If the command returned a CLIError, use its specific exit code
		// so that approve/deny and other commands exit with the correct code.
		var cliErr *cli.CLIError
		if errors.As(err, &cliErr) {
			os.Exit(cliErr.Code)
		}
		os.Exit(exitcode.UserError)
	}
}
