package cli

import (
	"github.com/spf13/cobra"
)

func newDrillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drill",
		Short: "Rehearse recovery",
	}
	cmd.AddCommand(newDrillRestoreCmd())
	return cmd
}

func newDrillRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore --manifest <file> --report <file>",
		Short: "Check on a fresh host that every backed-up secret is still there",
		Long: `Run on a host that has only the backend configured. The drill fetches each item
of the manifest, compares keyed hashes under the recovery passphrase and writes
{"ok", "failed", "missing", "duration"} to the report: the count of matching
items, then the paths of those that differ or are absent. It never writes a
value. The exit status is non-zero when anything failed or is missing.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			manifest, _ := c.Flags().GetString("manifest")
			report, _ := c.Flags().GetString("report")
			to, _ := c.Flags().GetString("backend")
			stdinPass, _ := c.Flags().GetBool("passphrase-stdin")
			rep, err := checkManifest(c, manifest, to, stdinPass)
			if err != nil {
				return err
			}
			return finishReport(c, report, rep)
		},
	}
	cmd.Flags().String("manifest", "", "manifest file written by 'migrate import' (required)")
	cmd.Flags().String("report", "/dev/stdout", "where to write the report (a file, - or /dev/stdout)")
	cmd.Flags().String("backend", "", "backend to restore from (default: the configured backend)")
	cmd.Flags().Bool("passphrase-stdin", false, "read the recovery passphrase from standard input")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}
