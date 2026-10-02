package cli

import "strings"

// cobraGeneratedErrorPrefixes lists the stable error-message prefixes
// produced by cobra and pflag for user-input problems: unknown command,
// wrong positional-arg count, and bad/missing flags. These errors are
// returned by cobra's own Find/ParseFlags/ValidateArgs machinery BEFORE any
// RunE handler ever runs, so no application code has had a chance to print
// them — cmd/keylatch/main.go uses IsCobraGeneratedError to decide whether
// it must print err.Error() itself (root.SilenceErrors=true means cobra
// never prints these on its own).
//
// This is deliberately a prefix allowlist rather than a blanket "print every
// unprinted error" rule: most application RunE handlers already write their
// own "Error: ..." message to stderr before returning a plain error, and
// reprinting err.Error() for those would duplicate the message. cobra/pflag
// errors never reach a RunE handler, so they are always safe to print here.
//
// Sourced from spf13/cobra@v1.10.2 (args.go) and spf13/pflag@v1.0.10
// (errors.go). If a future upgrade changes these strings, the effect is a
// missed print (falls back to the pre-existing doctor-hint-only behavior),
// never a double-print or a crash — safe to leave stale until the next audit.
var cobraGeneratedErrorPrefixes = []string{
	"unknown command ",         // cobra args.go: legacyArgs / NoArgs
	"invalid argument ",        // cobra args.go: OnlyValidArgs
	"requires at least ",       // cobra args.go: MinimumNArgs
	"accepts at most ",         // cobra args.go: MaximumNArgs
	"accepts between ",         // cobra args.go: RangeArgs
	"accepts ",                 // cobra args.go: ExactArgs
	"unknown flag: ",           // pflag errors.go: flagNotExistError
	"unknown shorthand flag: ", // pflag errors.go: flagNotExistError
	"flag needs an argument",   // pflag errors.go: ValueRequiredError
}

// IsCobraGeneratedError reports whether err looks like one of cobra's or
// pflag's own user-input errors (unknown command, wrong arg count, bad or
// missing flag) rather than an application error returned from a RunE
// handler. Exported so cmd/keylatch/main.go can decide whether printing
// err.Error() itself would duplicate a message the handler already wrote.
func IsCobraGeneratedError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, prefix := range cobraGeneratedErrorPrefixes {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}
