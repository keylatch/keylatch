package cli

import (
	"encoding/json"
	"fmt"
	goos "runtime"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/spf13/cobra"
)

// ModeEntry describes a single keylatch runtime mode for JSON and table output.
//
// Added Available, Reason, and Fix fields (§13.7).
type ModeEntry struct {
	Name          string `json:"name"`
	Available     bool   `json:"available"`
	UseWhen       string `json:"use_when"`
	SecurityLevel string `json:"security_level"`
	Requires      string `json:"requires"`
	Reason        string `json:"reason,omitempty"` // non-empty when !Available
	Fix           string `json:"fix,omitempty"`    // actionable hint when !Available
}

// newModesCmd returns the `keylatch modes` command.
// It is a read-only informational command — no side effects.
//
// Added --json flag directly on the command (not just global root flag),
// AVAILABLE and FIX columns, and removes the deleted direct_classic modes.
func newModesCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:     "modes",
		Short:   "List available runtime modes",
		GroupID: "daily",
		Long: `List the runtime modes keylatch supports for credential injection.

For most users: the default gateway_typed mode is what you want.
Use 'keylatch runtime doctor <provider>' for a per-provider recommendation.

Exits non-zero if any preferred mode is unavailable.`,
		RunE: func(c *cobra.Command, _ []string) error {
			// Determine if the gateway is currently running by checking the PID file.
			env := llmcontext.DefaultLookup
			pidPath := paths.GatewayPID(env)
			_, gatewayRunning := gatewayLiveness(pidPath)

			// Determine if the proxy is running.
			proxyRunning, _, _ := proxyLiveness(env)

			// Determine direct_classic_sandboxed availability.
			sandboxAvailable, sandboxReason, sandboxFix := sandboxModeAvailability()

			modes := []ModeEntry{
				{
					Name:          "gateway_typed",
					UseWhen:       "AI agents from a human terminal; gateway rewrites API endpoints to proxy through keylatch.",
					SecurityLevel: "High — credentials never leave keylatch",
					Requires:      "keylatch gateway up",
					Available:     gatewayRunning,
					Reason: func() string {
						if gatewayRunning {
							return ""
						}
						return "gateway not running"
					}(),
					Fix: func() string {
						if gatewayRunning {
							return ""
						}
						return "keylatch gateway up"
					}(),
				},
				{
					Name:          "gateway_sdk",
					UseWhen:       "Agent SDK accepts a custom base URL; keylatch injects a session token instead of the root API key.",
					SecurityLevel: "High — root key isolated",
					Requires:      "keylatch gateway up",
					Available:     gatewayRunning,
					Reason: func() string {
						if gatewayRunning {
							return ""
						}
						return "gateway not running"
					}(),
					Fix: func() string {
						if gatewayRunning {
							return ""
						}
						return "keylatch gateway up"
					}(),
				},
				{
					Name:          "direct_brokered",
					UseWhen:       "Provider supports short-lived scoped tokens; keylatch exchanges the root credential for a scoped one before launch.",
					SecurityLevel: "High — root credential zeroed after exchange",
					Requires:      "Broker strategy configured",
					Available:     true, // always locally available; broker errors surface at run-time
				},
				{
					Name:          "gateway_proxy",
					UseWhen:       "Full HTTP proxy interception (CONNECT-based); HTTPS traffic routed through keylatch. Experimental.",
					SecurityLevel: "Medium — requires trust-install",
					Requires:      "keylatch proxy up",
					Available:     proxyRunning,
					Reason: func() string {
						if proxyRunning {
							return ""
						}
						return "proxy not running"
					}(),
					Fix: func() string {
						if proxyRunning {
							return ""
						}
						return "keylatch proxy up"
					}(),
				},
				{
					// direct_classic_sandboxed reinstated.
					Name:          "direct_classic_sandboxed",
					UseWhen:       "Isolated subprocess execution via OS sandbox (bwrap/sandbox-exec). Credentials injected inside a filesystem-restricted container.",
					SecurityLevel: "High — ~/.keylatch denied inside sandbox; executable hash verified",
					Requires:      "bwrap (Linux) or sandbox-exec (macOS built-in)",
					Available:     sandboxAvailable,
					Reason:        sandboxReason,
					Fix:           sandboxFix,
				},
			}

			// Determine exit code: non-zero if any mode is unavailable.
			anyUnavailable := false
			for _, m := range modes {
				if !m.Available {
					anyUnavailable = true
					break
				}
			}

			// Also check global --json flag for backward compatibility.
			useGlobalJSON, _ := c.Root().PersistentFlags().GetBool("json")
			if jsonOut || useGlobalJSON {
				out, err := json.MarshalIndent(map[string]any{
					"_schema": "v1",
					"modes":   modes,
				}, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(c.OutOrStdout(), string(out))
				if anyUnavailable {
					return fmt.Errorf("one or more runtime modes are unavailable")
				}
				return nil
			}

			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "MODE\tAVAILABLE\tUSE WHEN\tFIX")
			fmt.Fprintln(tw, "----\t---------\t---------\t---")
			for _, m := range modes {
				avail := "yes"
				fix := ""
				if !m.Available {
					avail = "no (" + m.Reason + ")"
					fix = m.Fix
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Name, avail, m.UseWhen, fix)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "For per-provider mode availability: keylatch runtime doctor <provider>")
			fmt.Fprintln(c.OutOrStdout(), "Note: direct_classic was permanently removed in v1.0.0. Use: --runtime gateway_typed")
			fmt.Fprintln(c.OutOrStdout(), "Sandbox: direct_classic_sandboxed requires 'keylatch sandbox doctor' preflight check.")

			if anyUnavailable {
				return fmt.Errorf("one or more runtime modes are unavailable")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

// gatewayLiveness returns the gateway PID and whether it's running.
// Wraps gateway.IsRunning for use in modes_cmd.
func gatewayLiveness(pidPath string) (int, bool) {
	return gateway.IsRunning(pidPath)
}

// sandboxModeAvailability returns (available, reason, fix) for
// direct_classic_sandboxed on the current platform.
func sandboxModeAvailability() (available bool, reason, fix string) {
	switch goos.GOOS {
	case "windows":
		return false,
			"not supported on Windows",
			"Use --runtime gateway_typed on Windows"
	case "linux":
		if path, ok := sandbox.DetectBwrap(); ok {
			return true,
				fmt.Sprintf("bwrap found at %s", path),
				""
		}
		return false,
			"bwrap (bubblewrap) not found",
			"apt-get install bubblewrap | dnf install bubblewrap | pacman -S bubblewrap"
	default:
		// macOS and other POSIX: sandbox-exec is built-in.
		return true,
			"sandbox-exec built-in (macOS)",
			""
	}
}
