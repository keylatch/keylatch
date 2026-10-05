package cli

// audit_cmd.go implements the `keylatch audit` CLI command.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/audit/salt"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// newAuditCmd returns the `keylatch audit` command.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log inspection and management",
		Long:  "Inspect, rotate, and verify the append-only encrypted audit log.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default behaviour: --summary.
			return runAuditSummary(cmd)
		},
	}

	cmd.Flags().Bool("summary", false, "print audit summary (default)")
	cmd.Flags().Bool("raw", false, "verify chain integrity and print verification summary (blocked in LLM sessions)")
	cmd.Flags().Bool("rotate", false, "rotate the audit log")
	cmd.Flags().Bool("verify-chain", false, "verify HMAC chain integrity")
	cmd.Flags().String("since", "", "filter events since this RFC3339 timestamp (used with --summary)")
	cmd.Flags().String("service", "", "filter by service name")
	cmd.Flags().String("path", "", "filter by secret path")
	cmd.Flags().String("action", "", "filter by action")
	cmd.Flags().Bool("json", false, "output in JSON format")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		rotate, _ := cmd.Flags().GetBool("rotate")
		verifyChain, _ := cmd.Flags().GetBool("verify-chain")
		raw, _ := cmd.Flags().GetBool("raw")

		switch {
		case rotate:
			return runAuditRotate(cmd)
		case verifyChain:
			return runAuditVerifyChain(cmd)
		case raw:
			return runAuditRaw(cmd)
		default:
			return runAuditSummary(cmd)
		}
	}

	// §4.3: live tail, since, and retention prune subcommands.
	cmd.AddCommand(newAuditTailCmd())
	cmd.AddCommand(newAuditSinceCmd())
	cmd.AddCommand(newAuditRetentionCmd())

	return cmd
}

// openAuditLogger opens the audit logger using the environment config.
// auditDEK is loaded from the keyring via TTY or stdin pipe (not env var).
func openAuditLogger() (*audit.Logger, func(), error) {
	auditPath := paths.Audit(os.Getenv)
	saltPath := paths.AuditSalt(os.Getenv)

	// Ensure parent directory.
	auditDir := paths.ConfigDir(os.Getenv)
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("audit: mkdir config dir: %w", err)
	}

	saltBytes, err := salt.LoadOrCreate(saltPath)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: load salt: %w", err)
	}

	auditDEK, olderDEKs, err := loadAuditKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("audit: load DEK: %w", err)
	}

	l, err := audit.Open(auditPath, saltBytes, auditDEK)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: open: %w", err)
	}
	l.AddReadKeys(olderDEKs...)

	cleanup := func() {
		_ = l.Close()
		// Zero the auditDEK.
		clear(auditDEK)
		for _, k := range olderDEKs {
			clear(k)
		}
	}
	return l, cleanup, nil
}

// loadAuditKeys returns the DEK new audit events are sealed with and the
// older DEKs earlier events may be sealed with: retired terms of the same
// keyring and, where an install still has the legacy keyring beside the
// bootstrap one, that keyring's DEKs.
func loadAuditKeys() ([]byte, [][]byte, error) {
	kr, _, krPath, err := openKeyringFromEnv()
	if err != nil {
		return nil, nil, err
	}
	defer kr.Zero()
	dek, term, err := kr.ActiveDEK()
	if err != nil {
		return nil, nil, err
	}
	active := bytes.Clone(dek)
	older := retiredDEKs(kr, term)

	if legacy := paths.LegacyKeyringPath(os.Getenv); legacy != krPath {
		if _, statErr := os.Stat(legacy); statErr == nil {
			if lkr, _, _, openErr := openKeyringAt(legacy, false); openErr == nil {
				if ldek, lterm, dekErr := lkr.ActiveDEK(); dekErr == nil {
					older = append(older, bytes.Clone(ldek))
					older = append(older, retiredDEKs(lkr, lterm)...)
				}
				lkr.Zero()
			}
		}
	}
	return active, older, nil
}

func retiredDEKs(kr *keyring.Keyring, activeTerm int) [][]byte {
	var out [][]byte
	for t := activeTerm - 1; t >= 1; t-- {
		if dek, err := kr.DEKForTerm(t); err == nil {
			out = append(out, bytes.Clone(dek))
		}
	}
	return out
}

// runAuditSummary implements `keylatch audit [--summary]`.
func runAuditSummary(cmd *cobra.Command) error {
	l, cleanup, err := openAuditLogger()
	if err != nil {
		return err
	}
	defer cleanup()

	opts := audit.SummaryOpts{}

	if sinceStr, _ := cmd.Flags().GetString("since"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			return fmt.Errorf("audit: parse --since: %w", err)
		}
		opts.Since = t
	}
	if svc, _ := cmd.Flags().GetString("service"); svc != "" {
		opts.Service = svc
	}
	if p, _ := cmd.Flags().GetString("path"); p != "" {
		opts.Path = p
	}
	if act, _ := cmd.Flags().GetString("action"); act != "" {
		opts.Action = audit.Action(act)
	}

	sum, err := l.Summarize(opts)
	if err != nil {
		return fmt.Errorf("audit: summarize: %w", err)
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		out, _ := json.MarshalIndent(sum, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "total_events: %d\n", sum.TotalEvents)
	if !sum.OldestEvent.IsZero() {
		fmt.Fprintf(w, "oldest: %s\n", sum.OldestEvent.Format(time.RFC3339))
		fmt.Fprintf(w, "newest: %s\n", sum.NewestEvent.Format(time.RFC3339))
	}
	if len(sum.ByAction) > 0 {
		fmt.Fprintln(w, "by_action:")
		for action, count := range sum.ByAction {
			fmt.Fprintf(w, "  %s: %d\n", action, count)
		}
	}
	if len(sum.ByOutcome) > 0 {
		fmt.Fprintln(w, "by_outcome:")
		for outcome, count := range sum.ByOutcome {
			fmt.Fprintf(w, "  %s: %d\n", outcome, count)
		}
	}
	return nil
}

// runAuditRaw implements `keylatch audit --raw`.
// Blocked in LLM sessions.
func runAuditRaw(cmd *cobra.Command) error {
	if llmcontext.IsLLMSession(os.Getenv) {
		return fmt.Errorf("audit --raw: blocked in LLM session")
	}

	auditPath := paths.Audit(os.Getenv)
	saltPath := paths.AuditSalt(os.Getenv)

	saltBytes, err := salt.LoadOrCreate(saltPath)
	if err != nil {
		return fmt.Errorf("audit: load salt: %w", err)
	}

	auditDEK, olderDEKs, err := loadAuditKeys()
	if err != nil {
		return fmt.Errorf("audit: load DEK: %w", err)
	}
	defer func() {
		clear(auditDEK)
		for _, k := range olderDEKs {
			clear(k)
		}
	}()

	// Delegate to VerifyChain with full AEAD mode but stream the events.
	// Use a raw file read + decrypt loop.
	report, err := audit.VerifyChain(auditPath, saltBytes, auditDEK, olderDEKs...)
	if err != nil {
		return fmt.Errorf("audit --raw: %w", err)
	}

	// VerifyChain already validates; for raw output we print the report summary.
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "total_lines: %d\n", report.TotalLines)
	fmt.Fprintf(w, "verified: %d\n", report.Verified)
	if report.FirstBadLine > 0 {
		fmt.Fprintf(w, "first_bad_line: %d\n", report.FirstBadLine)
		fmt.Fprintf(w, "reason: %s\n", report.FirstBadReason)
	}
	return nil
}

// runAuditRotate implements `keylatch audit --rotate`.
func runAuditRotate(cmd *cobra.Command) error {
	l, cleanup, err := openAuditLogger()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := l.Rotate(); err != nil {
		return fmt.Errorf("audit --rotate: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "audit log rotated")
	return nil
}

// runAuditVerifyChain implements `keylatch audit --verify-chain`.
// Exits non-zero if any bad lines found.
func runAuditVerifyChain(cmd *cobra.Command) error {
	auditPath := paths.Audit(os.Getenv)
	saltPath := paths.AuditSalt(os.Getenv)

	saltBytes, err := salt.LoadOrCreate(saltPath)
	if err != nil {
		return fmt.Errorf("audit --verify-chain: load salt: %w", err)
	}

	// Use header-only mode (no DEK) by default.
	// Full mode is available internally but not exposed here to avoid
	// requiring the keyring password just for chain integrity checks.
	report, err := audit.VerifyChain(auditPath, saltBytes, nil)
	if err != nil {
		return fmt.Errorf("audit --verify-chain: %w", err)
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	w := cmd.OutOrStdout()

	if asJSON {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Fprintln(w, string(out))
	} else {
		fmt.Fprintf(w, "total_lines: %d\n", report.TotalLines)
		fmt.Fprintf(w, "verified: %d\n", report.Verified)
		if report.FirstBadLine > 0 {
			fmt.Fprintf(w, "first_bad_line: %d\n", report.FirstBadLine)
			fmt.Fprintf(w, "reason: %s\n", report.FirstBadReason)
		} else {
			fmt.Fprintln(w, "chain_ok: true")
		}
	}

	// Non-zero exit if tampered.
	if report.FirstBadLine > 0 {
		return fmt.Errorf("audit chain integrity failure at line %d: %s", report.FirstBadLine, report.FirstBadReason)
	}
	return nil
}
