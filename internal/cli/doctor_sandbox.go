package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/contained"
)

// writeSandboxReport prints what the host lets the contained tier do.
func writeSandboxReport(w io.Writer, r contained.Report, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(struct {
			Schema string `json:"_schema"`
			contained.Report
		}{"v1", r}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	fmt.Fprintf(w, "keylatch doctor --sandbox: backend=%s\n\n", r.Backend)
	for _, c := range r.Capabilities {
		icon := "[ ok ]"
		if !c.OK {
			icon = "[warn]"
			if slices.ContainsFunc(r.Missing(), func(m string) bool { return strings.HasPrefix(m, c.Name+":") }) {
				icon = "[FAIL]"
			}
		}
		fmt.Fprintf(w, "  %s %s: %s\n", icon, c.Name, c.Detail)
	}
	if r.Supported {
		fmt.Fprintln(w, "\nThe contained tier (D5) is available.")
	} else {
		fmt.Fprintln(w, "\nThe contained tier (D5) is unavailable until the failing checks pass; no run falls back to an uncontained one.")
	}
	return nil
}

// sandboxExitCode mirrors the doctor exit codes: 0 when every capability is
// present, 1 when only optional ones are missing, 2 when D5 cannot run.
func sandboxExitCode(r contained.Report) int {
	switch {
	case !r.Supported:
		return doctorExitFailure
	default:
		for _, c := range r.Capabilities {
			if !c.OK {
				return doctorExitWarnings
			}
		}
		return doctorExitOK
	}
}
