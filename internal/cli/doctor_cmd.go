package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	klruntime "github.com/keylatch/keylatch/internal/runtime"
	"github.com/spf13/cobra"
)

// doctorJSONV1 is the JSON schema v1 output shape for `keylatch doctor --json`.
//
// It embeds the existing doctor.Report so that consumers relying on the old
// JSON shape (OverallOK, Version, Platform, etc.) continue to work. The new
// v1 fields (_schema, exit, summary, operating_mode) are added alongside.
//
// Fields:
//   - _schema: always "v1" — stable schema identifier for consumers.
//   - exit: the exit code that the command produces (0, 1, or 2).
//   - summary: aggregate counts by status.
//   - operating_mode: resolved operating mode name (EPIC-17).
//   - All doctor.Report fields preserved for backward compatibility.
type doctorJSONV1 struct {
	doctor.Report
	Schema        string          `json:"_schema"`
	Exit          int             `json:"exit"`
	Summary       doctorSummaryV1 `json:"summary"`
	OperatingMode string          `json:"operating_mode"`
}

// doctorSummaryV1 holds aggregate counts.
type doctorSummaryV1 struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// buildDoctorJSONV1 converts a doctor.Report to the v1 JSON shape.
func buildDoctorJSONV1(report doctor.Report, exitCode int) doctorJSONV1 {
	var summary doctorSummaryV1
	for _, s := range report.Checks {
		if !s.OK {
			summary.Fail++
		} else if s.Warn {
			summary.Warn++
		} else {
			summary.OK++
		}
	}

	// EPIC-17: resolve operating mode for JSON output.
	operatingMode := resolveOperatingModeForDoctor()

	return doctorJSONV1{
		Report:        report,
		Schema:        "v1",
		Exit:          exitCode,
		Summary:       summary,
		OperatingMode: operatingMode,
	}
}

// resolveOperatingModeForDoctor reads the config and resolves the effective
// operating mode name for inclusion in doctor JSON output.
func resolveOperatingModeForDoctor() string {
	cfgPath := paths.Config(llmcontext.DefaultLookup)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = config.Default()
	}
	resolved, resolveErr := klruntime.ResolveMode("", klruntime.OperatingMode(cfg.Mode))
	if resolveErr != nil {
		return "unknown"
	}
	return resolved.String()
}

// Doctor exit codes (local to this command — not global exitcode constants).
// Exit 0: all checks OK (warnings are informational only).
// Exit 1: warnings present but no blocking failures.
// Exit 2: at least one check has OK==false (blocking failure).
const (
	doctorExitOK       = 0
	doctorExitWarnings = 1
	doctorExitFailure  = 2
)

// newDoctorCmdImpl returns the fully-implemented `doctor` subcommand.
// NOT guarded by GuardLLMSession — doctor is diagnostic-only, value-free.
func newDoctorCmdImpl() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose keylatch configuration and environment",
		Long: `Doctor runs a series of diagnostic checks and reports on the health of
your keylatch installation.

Exit codes:
  0 — all checks passed (warnings are informational only)
  1 — warnings present but no blocking failures
  2 — at least one check failed (blocking failure)`,
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			verbose, _ := c.Flags().GetBool("verbose")
			redactPaths, _ := c.Flags().GetBool("redact-paths")
			quiet, _ := c.Flags().GetBool("quiet")
			categoryStr, _ := c.Flags().GetString("category")

			var categories []string
			if categoryStr != "" {
				for _, cat := range strings.Split(categoryStr, ",") {
					if t := strings.TrimSpace(cat); t != "" {
						categories = append(categories, t)
					}
				}
			}

			report, err := doctor.Run(c.Context(), doctor.Options{
				JSON:        jsonOut,
				Verbose:     verbose || jsonOut, // JSON always shows all checks
				RedactPaths: redactPaths,
				Quiet:       quiet,
				Categories:  categories,
				Env:         llmcontext.DefaultLookup,
			})
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "doctor: %v\n", err)
				os.Exit(doctorExitFailure)
			}

			// Determine exit code (three-tier: C2).
			// Exit 0: all checks OK with no warnings.
			// Exit 1: all checks OK but at least one warning.
			// Exit 2: at least one check has OK==false (blocking failure).
			exitCode := doctorExitOK
			if !report.OverallOK {
				exitCode = doctorExitFailure
			} else if report.HasWarnings {
				exitCode = doctorExitWarnings
			}

			if jsonOut {
				v1 := buildDoctorJSONV1(report, exitCode)
				b, marshalErr := json.MarshalIndent(v1, "", "  ")
				if marshalErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "doctor: marshal: %v\n", marshalErr)
					os.Exit(doctorExitFailure)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
			} else if !quiet {
				printDoctorReport(c, report)
			}

			os.Exit(exitCode)
			return nil
		},
	}

	cmd.Flags().Bool("json", false, "output as JSON (v1 schema: _schema, exit, checks, summary)")
	cmd.Flags().Bool("verbose", false, "show all checks, including passing ones")
	cmd.Flags().Bool("redact-paths", false, "hash path values in output (for support bundles)")
	cmd.Flags().Bool("repair", false, "attempt supported repairs for failed checks")
	cmd.Flags().Bool("yes", false, "confirm repair prompts")
	cmd.Flags().Bool("quiet", false, "suppress table output; only exits with the appropriate code")
	cmd.Flags().String("category", "", "comma-separated list of categories to run (e.g. environment,backends)")
	// NOTE(epic-16): --connection flag for gateway scoping is deferred.

	return cmd
}

// sectionTitle maps section identifiers to display titles.
var sectionTitle = map[string]string{
	"environment": "Environment",
	"daemon":      "Daemon",
	"backends":    "Backends",
	"external":    "External Stores (EPIC-10)",
	"providers":   "Providers",
}

// sectionDisplayOrder defines the canonical order sections appear in output.
// "external" appears after "backends" so PM CLI checks follow credential-store checks.
var sectionDisplayOrder = []string{"environment", "daemon", "backends", "external", "providers"}

// printDoctorReport renders a section-grouped human-readable doctor report.
func printDoctorReport(c *cobra.Command, report doctor.Report) {
	w := c.OutOrStdout()
	fmt.Fprintf(w, "keylatch doctor — version=%s platform=%s\n", report.Version, report.Platform)

	if report.LLMSession {
		fmt.Fprintf(w, "\n  [WARN] LLM session detected: %s\n", strings.Join(report.LLMReasons, ", "))
	}

	// Group checks by section for display.
	bySection := make(map[string][]doctor.Status)
	var unsectioned []doctor.Status
	for _, s := range report.Checks {
		if s.Section == "" {
			unsectioned = append(unsectioned, s)
			continue
		}
		bySection[s.Section] = append(bySection[s.Section], s)
	}

	sep := strings.Repeat("─", 37) // ─────────────────────────────────────

	printed := false
	for _, sec := range sectionDisplayOrder {
		checks, ok := bySection[sec]
		if !ok {
			continue
		}
		fmt.Fprintln(w)
		title := sectionTitle[sec]
		if title == "" {
			title = sec
		}
		fmt.Fprintf(w, "  %s\n", title)
		fmt.Fprintf(w, "  %s\n", sep)
		for _, s := range checks {
			printStatusLine(w, s)
		}
		printed = true
	}

	// Fallback: checks with no section (shouldn't happen in practice).
	if len(unsectioned) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  Other\n")
		fmt.Fprintf(w, "  %s\n", sep)
		for _, s := range unsectioned {
			printStatusLine(w, s)
		}
		printed = true
	}
	_ = printed

	// Summary line.
	fmt.Fprintln(w)
	failures := 0
	warnings := 0
	for _, s := range report.Checks {
		if !s.OK {
			failures++
		} else if s.Warn {
			warnings++
		}
	}

	switch {
	case failures > 0 && warnings > 0:
		fmt.Fprintf(w, "Overall: %d failure(s), %d warning(s)\n", failures, warnings)
		fmt.Fprintln(w, "Exit code: 2 (blocking failures present)")
	case failures > 0:
		fmt.Fprintf(w, "Overall: %d failure(s)\n", failures)
		fmt.Fprintln(w, "Exit code: 2 (blocking failures present)")
	case warnings > 0:
		fmt.Fprintf(w, "Overall: %d warning(s)\n", warnings)
		fmt.Fprintln(w, "Exit code: 1 (warnings only)")
	default:
		fmt.Fprintln(w, "Overall: OK")
	}
}

// printStatusLine writes a single check line (and optional fix line) to w.
func printStatusLine(w interface{ Write([]byte) (int, error) }, s doctor.Status) {
	icon := "[ ok ]"
	if !s.OK {
		icon = "[FAIL]"
	} else if s.Warn {
		icon = "[warn]"
	}
	fmt.Fprintf(w, "  %s %s: %s\n", icon, s.Name, s.Detail)
	if s.Fix != "" && (!s.OK || s.Warn) {
		fmt.Fprintf(w, "         fix: %s\n", s.Fix)
	}
}
