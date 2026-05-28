// Package cmderr provides structured CLI error formatting for keylatch.
// It defines the E error type with Summary/Cause/Hint/Code fields and a
// Format function that renders a human-readable block to an io.Writer.
package cmderr

import (
	"fmt"
	"io"
)

// E is a structured CLI error.
type E struct {
	Summary string // one-line user-facing message
	Cause   error  // underlying error (optional)
	Hint    string // fix suggestion (optional)
	Code    string // short error code, e.g. "team-auth", "policy-list" (optional)
}

// Error returns the one-line Summary. Implements the error interface.
func (e *E) Error() string {
	return e.Summary
}

// Unwrap returns the underlying Cause. Implements errors.Unwrap.
func (e *E) Unwrap() error {
	return e.Cause
}

// Wrap constructs a structured CLI error.
func Wrap(summary string, cause error, hint string, code string) *E {
	return &E{
		Summary: summary,
		Cause:   cause,
		Hint:    hint,
		Code:    code,
	}
}

// Format renders the full human-readable error block to w.
// Omits Cause/Fix/Docs lines when those fields are empty/nil.
//
// Output format:
//
//	Error: <summary>
//	  Cause: <cause.Error()>
//	  Fix:   <hint>
//	  Docs:  keylatch.dev/errors/<code>
func Format(w io.Writer, err *E) {
	fmt.Fprintf(w, "Error: %s\n", err.Summary)
	if err.Cause != nil {
		fmt.Fprintf(w, "  Cause: %s\n", err.Cause.Error())
	}
	if err.Hint != "" {
		fmt.Fprintf(w, "  Fix:   %s\n", err.Hint)
	}
	if err.Code != "" {
		fmt.Fprintf(w, "  Docs:  keylatch.dev/errors/%s\n", err.Code)
	}
}
