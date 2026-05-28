package cli

// audit_tail_cmd.go implements `keylatch audit tail` and `keylatch audit since`.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// ParseDurationPublic is the exported alias of parseDuration for package-external tests.
var ParseDurationPublic = parseDuration

// parseDuration parses human-friendly durations used by `audit since`.
// Accepts standard Go durations (1h, 30m) plus day shorthand (7d, 30d).
func parseDuration(s string) (time.Duration, error) {
	// Handle day suffix manually: Go's time.ParseDuration does not accept 'd'.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days, err := parsePositiveInt(s[:len(s)-1])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: valid examples: 1h, 24h, 7d, 30d", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return d, nil
}

// parsePositiveInt parses a positive integer from s.
func parsePositiveInt(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-numeric character %q", c)
		}
		n = n*10 + int64(c-'0')
	}
	if n <= 0 {
		return 0, fmt.Errorf("value must be positive")
	}
	return n, nil
}

// prettyEvent formats an audit event for human-readable output.
func prettyEvent(e audit.Event) string {
	ts := e.Timestamp.Format("2006-01-02 15:04:05")
	actor := e.Actor
	if actor == "" {
		actor = "-"
	}
	provider := e.Backend
	if provider == "" {
		provider = "-"
	}
	return fmt.Sprintf("%s  %-20s  %-20s  %-8s  %s",
		ts, actor, provider, string(e.Outcome), string(e.Action))
}

// newAuditTailCmd returns the `keylatch audit tail` subcommand.
// §4.3: show the tail of the audit log or live-follow with -f.
func newAuditTailCmd() *cobra.Command {
	var (
		asJSON bool
		follow bool
		lines  int
	)

	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Follow or show the tail of the audit log",
		Long: `Show recent audit log entries and optionally follow new events.

Without -f: print the last N lines (default 20) and exit, like tail(1).
With -f: live-follow and print new events as they arrive. Press Ctrl-C to stop.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, cleanup, err := openAuditLogger()
			if err != nil {
				return err
			}
			defer cleanup()

			w := cmd.OutOrStdout()

			// No -f: scan all events and print the last `lines` of them.
			if !follow {
				events, err := l.Scan(audit.SinceOpts{})
				if err != nil {
					return fmt.Errorf("audit tail: %w", err)
				}
				start := 0
				if len(events) > lines {
					start = len(events) - lines
				}
				tail := events[start:]
				if !asJSON {
					fmt.Fprintf(w, "%-19s  %-20s  %-20s  %-8s  %s\n",
						"TIMESTAMP", "AGENT", "PROVIDER", "OUTCOME", "ACTION")
				}
				for _, e := range tail {
					if asJSON {
						b, _ := json.Marshal(e)
						fmt.Fprintln(w, string(b))
					} else {
						fmt.Fprintln(w, prettyEvent(e))
					}
				}
				return nil
			}

			// -f: live-follow.
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			ch := make(chan audit.Event, 32)
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case e := <-ch:
						if asJSON {
							b, _ := json.Marshal(e)
							fmt.Fprintln(w, string(b))
						} else {
							fmt.Fprintln(w, prettyEvent(e))
						}
					}
				}
			}()

			if !asJSON {
				fmt.Fprintln(w, "Watching audit log. Press Ctrl-C to stop.")
				fmt.Fprintln(w)
				fmt.Fprintf(w, "%-19s  %-20s  %-20s  %-8s  %s\n",
					"TIMESTAMP", "AGENT", "PROVIDER", "OUTCOME", "ACTION")
			}

			return l.Tail(ctx, audit.TailOpts{}, ch)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "live-follow new events (Ctrl-C to stop)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON Lines format (machine-readable)")
	cmd.Flags().IntVarP(&lines, "lines", "n", 20, "number of lines to show (without -f)")
	return cmd
}

// newAuditSinceCmd returns the `keylatch audit since <duration>` subcommand.
// §4.3: show events from the past duration with optional filters.
func newAuditSinceCmd() *cobra.Command {
	var (
		asJSON   bool
		agent    string
		provider string
		outcome  string
	)

	cmd := &cobra.Command{
		Use:   "since <duration>",
		Short: "Show audit events from the past duration",
		Long: `Show audit events from the past duration.

Duration examples: 1h, 24h, 7d, 30d

Filter flags:
  --agent <name>    filter by agent/actor name
  --provider <name> filter by provider/backend name
  --outcome <value> filter by outcome: ok, denied, error`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := parseDuration(args[0])
			if err != nil {
				return err
			}
			since := time.Now().Add(-d)

			// Validate outcome flag.
			if outcome != "" {
				switch audit.Outcome(outcome) {
				case audit.OutcomeOK, audit.OutcomeDenied, audit.OutcomeError, audit.OutcomeWarn:
				default:
					return fmt.Errorf("invalid --outcome %q: must be one of: ok, denied, error, warn", outcome)
				}
			}

			l, cleanup, err := openAuditLogger()
			if err != nil {
				return err
			}
			defer cleanup()

			events, err := l.Scan(audit.SinceOpts{
				Since:    since,
				Agent:    agent,
				Provider: provider,
				Outcome:  audit.Outcome(outcome),
			})
			if err != nil {
				return fmt.Errorf("audit since: %w", err)
			}

			w := cmd.OutOrStdout()
			if asJSON {
				for _, e := range events {
					b, _ := json.Marshal(e)
					fmt.Fprintln(w, string(b))
				}
				return nil
			}

			if len(events) == 0 {
				fmt.Fprintf(w, "No audit events in the past %s.\n", args[0])
				return nil
			}

			fmt.Fprintf(w, "%-19s  %-20s  %-20s  %-8s  %s\n",
				"TIMESTAMP", "AGENT", "PROVIDER", "OUTCOME", "ACTION")
			for _, e := range events {
				fmt.Fprintln(w, prettyEvent(e))
			}
			fmt.Fprintf(w, "\n%d event(s) in the past %s.\n", len(events), args[0])
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON Lines format (SIEM-compatible)")
	cmd.Flags().StringVar(&agent, "agent", "", "filter by agent/actor name")
	cmd.Flags().StringVar(&provider, "provider", "", "filter by provider/backend name")
	cmd.Flags().StringVar(&outcome, "outcome", "", "filter by outcome: ok, denied, error, warn")

	return cmd
}

// runAuditRetentionSweep prunes audit entries older than retentionDays.
// Returns the number of pruned entries (0 on no-op).
func runAuditRetentionSweep(retentionDays int) (int, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	l, cleanup, err := openAuditLogger()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	n, err := l.Prune(cutoff)
	if err != nil {
		return 0, fmt.Errorf("audit retention sweep: %w", err)
	}
	return n, nil
}

// newAuditRetentionCmd returns the `keylatch audit prune` subcommand.
// Exposed as a manual command; the daemon also calls runAuditRetentionSweep.
func newAuditRetentionCmd() *cobra.Command {
	var days int

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove audit entries older than retention_days",
		Long: `Remove audit log entries older than the configured retention period.

The default retention is 30 days. Override with --days or set
audit.retention_days in keylatch.yaml.

This command is also run automatically at daemon start and daily thereafter.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			retentionDays := days
			if retentionDays <= 0 {
				// Load from config.
				retentionDays = loadRetentionDays(paths.Config(llmcontext.DefaultLookup))
			}
			n, err := runAuditRetentionSweep(retentionDays)
			if err != nil {
				return err
			}
			if n == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "audit prune: nothing to prune")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "audit prune: removed %d entries older than %d days\n", n, retentionDays)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 0, "retention period in days (default: config audit.retention_days or 30)")
	return cmd
}

// loadRetentionDays reads audit.retention_days from the keylatch config file.
// Falls back to 30 on any error (file missing, parse error, zero value).
func loadRetentionDays(configPath string) int {
	cfg, err := config.Load(configPath)
	if err != nil {
		return 30
	}
	if cfg.Audit.RetentionDays <= 0 {
		return 30
	}
	return cfg.Audit.RetentionDays
}
