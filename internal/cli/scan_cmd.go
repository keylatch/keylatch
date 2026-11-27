package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/masking"
)

var canaryMarkerRE = regexp.MustCompile(`klc-canary-[a-z0-9_]+-[0-9a-f]{16}`)

// scanFinding is one line that holds a credential or a canary. It names the
// place and the kind, never the value.
type scanFinding struct {
	Source string
	Line   int
	Kind   string
}

// scanLines reads r line by line and returns where credentials appear and the
// text with them redacted.
func scanLines(source string, r io.Reader) ([]scanFinding, string, error) {
	var findings []scanFinding
	var out strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		clean := canaryMarkerRE.ReplaceAllString(line, "[REDACTED]")
		if clean != line {
			findings = append(findings, scanFinding{source, n, "canary"})
		}
		if redacted := masking.RedactForLog(clean); redacted != clean {
			findings = append(findings, scanFinding{source, n, "credential"})
			clean = redacted
		}
		out.WriteString(clean)
		out.WriteByte('\n')
	}
	return findings, out.String(), sc.Err()
}

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Find credentials in text before it reaches a model or a transcript",
		Long: `scan reads the named files, or standard input, and reports every line that holds
a credential in a known format or a Keylatch canary. It prints the file, the line
and the kind of finding, never the value, and exits 2 when it finds anything, so a
hook can stop a prompt or a tool result from leaving.

With --redact the text is written to standard output with each finding replaced and
the exit status is 0, for filtering output on its way to a model.`,
		RunE: func(c *cobra.Command, args []string) error {
			redact, _ := c.Flags().GetBool("redact")
			var all []scanFinding
			scan := func(name string, r io.Reader) error {
				findings, text, err := scanLines(name, r)
				if err != nil {
					return fmt.Errorf("scan %s: %w", name, err)
				}
				all = append(all, findings...)
				if redact {
					_, err = io.WriteString(c.OutOrStdout(), text)
				}
				return err
			}
			if len(args) == 0 {
				if err := scan("<stdin>", c.InOrStdin()); err != nil {
					return err
				}
			}
			for _, path := range args {
				f, err := os.Open(path) //nolint:gosec // G304: the caller names the file to scan
				if err != nil {
					return err
				}
				err = scan(path, f)
				_ = f.Close()
				if err != nil {
					return err
				}
			}
			if redact {
				return nil
			}
			for _, f := range all {
				fmt.Fprintf(c.ErrOrStderr(), "%s:%d: %s\n", f.Source, f.Line, f.Kind)
			}
			if len(all) > 0 {
				return &CLIError{Class: "SecurityBlock", Code: 2, Message: fmt.Sprintf("%d finding(s): the text holds a credential", len(all)), Quiet: false}
			}
			return nil
		},
	}
	cmd.Flags().Bool("redact", false, "write the text to standard output with each finding replaced, and exit 0")
	return cmd
}
