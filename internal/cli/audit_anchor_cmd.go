package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/audit/salt"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// auditKeysForRead loads the chain seed and DEKs for commands that only read
// the log.
func auditKeysForRead(command string) (*auditKeys, error) {
	saltBytes, err := salt.LoadOrCreate(paths.AuditSalt(os.Getenv))
	if err != nil {
		return nil, fmt.Errorf("%s: load salt: %w", command, err)
	}
	keys, err := loadAuditKeyMaterial(saltBytes, false)
	if err != nil {
		return nil, fmt.Errorf("%s: load keys: %w", command, err)
	}
	return keys, nil
}

func newAuditHeadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "head",
		Short: "Print the sequence number, hash and key id of the audit log's last entry",
		Long: `Print the head of the audit log: the sequence number and chain hash of its
last entry, when it was written and which chain key produced the hash. Keep the
output (for example in a ticket or another machine) and pass it to
'keylatch audit verify --anchor' later to detect entries removed from the end.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if brokerInstalled(llmcontext.DefaultLookup) {
				return brokerAuditHead(c, llmcontext.DefaultLookup)
			}
			keys, err := auditKeysForRead("audit head")
			if err != nil {
				return err
			}
			defer keys.zero()
			head, err := audit.ReadHead(paths.Audit(os.Getenv), keys.seed)
			if err != nil {
				return fmt.Errorf("audit head: %w", err)
			}
			if asJSON, _ := c.Flags().GetBool("json"); asJSON {
				return json.NewEncoder(c.OutOrStdout()).Encode(head)
			}
			fmt.Fprintf(c.OutOrStdout(), "seq: %d\nhash: %s\ntime: %s\nkey_id: %s\n", head.Seq, head.Hash, head.Time.Format(time.RFC3339), head.KeyID)
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "output {seq, hash, time, key_id} as JSON")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit chain, and optionally that an anchor appears in it",
		Long: `Verify the HMAC chain of the audit log. With --anchor <file>, also check that the
sequence number and hash recorded by 'keylatch audit head --json' appear in the
log: a log truncated after the anchor was taken fails.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			keys, err := auditKeysForRead("audit verify")
			if err != nil {
				return err
			}
			defer keys.zero()
			auditPath := paths.Audit(os.Getenv)

			report, err := audit.VerifyChain(auditPath, keys.seed, nil)
			if err != nil {
				return fmt.Errorf("audit verify: %w", err)
			}
			result := map[string]any{"total_lines": report.TotalLines, "verified": report.Verified, "chain_ok": report.FirstBadLine == 0}
			var failure error
			if report.FirstBadLine > 0 {
				result["first_bad_line"], result["reason"] = report.FirstBadLine, report.FirstBadReason
				failure = fmt.Errorf("audit chain integrity failure at line %d: %s", report.FirstBadLine, report.FirstBadReason)
			}

			if anchorPath, _ := c.Flags().GetString("anchor"); anchorPath != "" && failure == nil {
				anchor, aerr := readAnchorFile(anchorPath)
				if aerr == nil {
					aerr = audit.VerifyAnchor(auditPath, keys.seed, anchor)
				}
				result["anchor_ok"] = aerr == nil
				if aerr != nil {
					result["anchor_error"] = aerr.Error()
					failure = fmt.Errorf("audit anchor check failed: %w", aerr)
				}
			}

			if asJSON, _ := c.Flags().GetBool("json"); asJSON {
				_ = json.NewEncoder(c.OutOrStdout()).Encode(result)
			} else {
				w := c.OutOrStdout()
				fmt.Fprintf(w, "total_lines: %d\nverified: %d\n", report.TotalLines, report.Verified)
				if failure == nil {
					fmt.Fprintln(w, "chain_ok: true")
				}
				if ok, present := result["anchor_ok"].(bool); present && ok {
					fmt.Fprintln(w, "anchor_ok: true")
				}
			}
			return failure
		},
	}
	cmd.Flags().String("anchor", "", "file holding the output of 'audit head --json' to check against the log")
	cmd.Flags().Bool("json", false, "output the result as JSON")
	return cmd
}

func readAnchorFile(path string) (audit.Head, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the anchor file the operator named
	if err != nil {
		return audit.Head{}, fmt.Errorf("read anchor: %w", err)
	}
	var h audit.Head
	if err := json.Unmarshal(data, &h); err != nil {
		return audit.Head{}, fmt.Errorf("parse anchor: %w", err)
	}
	if h.Seq < 1 || h.Hash == "" {
		return audit.Head{}, errors.New("anchor names no entry")
	}
	return h, nil
}

func newAuditExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit events as JSON Lines, verifying the chain on the way",
		Long: `Write the audit events in a time range as JSON Lines. Every line holds the
event (names and counters, never values) with its file, sequence number and chain
hash. The chain of each log file that can hold events in the range is verified
first and nothing is written when it fails. Blocked in LLM sessions.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				return NewSecurityBlock("audit export is blocked in LLM sessions")
			}
			format, _ := c.Flags().GetString("format")
			if format != "jsonl" {
				return withExitCode(exitcode.UserError, fmt.Errorf("audit export: unsupported --format %q (only jsonl)", format))
			}
			var opts audit.ExportOpts
			for flag, dst := range map[string]*time.Time{"since": &opts.Since, "until": &opts.Until} {
				v, _ := c.Flags().GetString(flag)
				if v == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, v)
				if err != nil {
					return withExitCode(exitcode.UserError, fmt.Errorf("audit export: --%s must be RFC3339: %w", flag, err))
				}
				*dst = t
			}

			keys, err := auditKeysForRead("audit export")
			if err != nil {
				return err
			}
			defer keys.zero()
			events, err := audit.Export(paths.Audit(os.Getenv), keys.seed, keys.dek, keys.older, opts)
			if err != nil {
				return fmt.Errorf("audit export: %w", err)
			}

			out := c.OutOrStdout()
			if path, _ := c.Flags().GetString("output"); path != "" {
				f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: the output file the operator named
				if err != nil {
					return fmt.Errorf("audit export: %w", err)
				}
				defer f.Close() //nolint:errcheck // flushed by the writes below
				out = f
			}
			enc := json.NewEncoder(out)
			for _, e := range events {
				if err := enc.Encode(e); err != nil {
					return fmt.Errorf("audit export: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().String("since", "", "first event time to export (RFC3339)")
	cmd.Flags().String("until", "", "last event time to export (RFC3339)")
	cmd.Flags().String("format", "jsonl", "output format (jsonl)")
	cmd.Flags().String("output", "", "write to this file (mode 0600) instead of stdout")
	return cmd
}
