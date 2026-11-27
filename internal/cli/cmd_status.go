package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// newTestCmd returns the `test` command.
//
// `test` reads a root credential via connections.Test →
// connections.RunTestStrategy → store.Get. This is a value-bearing path.
// LLM session guard: IsLLMSession check at the top of RunE blocks the command
// in LLM sessions with SecurityBlock exit code (exit 2).
func newTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <connection>",
		Short: "Test a connection's health",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			// value-bearing path — block in LLM sessions.
			// connections.Test reads the root credential to make an HTTP connectivity
			// probe. This must not run in LLM sessions.
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: 'test' reads a credential — blocked in LLM session (exit 2)\n")
				os.Exit(exitcode.SecurityBlock)
			}

			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			result, err := connections.Test(ctx, args[0], "", "default", store, nil)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			fmt.Fprintf(c.OutOrStdout(), "Status: %s (duration: %s)\n",
				result.Status, result.Duration)

			if result.Status != connections.TestStatusConnected {
				os.Exit(exitcode.UserError)
			}
			return nil
		},
	}
}

// newStatusCmd returns the `status` command — a system dashboard.
// Replaces one-line-per-connection output with a rich dashboard.
func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show system dashboard: vault, gateway, LLM session, connections",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup
			store := newDispatchedStore(cfg, env)

			namespace, _ := c.Flags().GetString("namespace")
			useJSON, _ := c.Flags().GetBool("json")

			statuses, err := connections.Status(ctx, connections.StatusOptions{
				Namespace: namespace,
			}, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			custom := loadCustomSecretsForDisplay(c, env)

			if useJSON {
				type jsonOut struct {
					Backend       string                         `json:"backend"`
					Connections   []connections.ConnectionStatus `json:"connections"`
					CustomSecrets []customsecret.Secret          `json:"custom_secrets"`
					Gateway       gatewayStatusInfo              `json:"gateway"`
					LLMSession    bool                           `json:"llm_session"`
				}
				gw := detectGatewayStatus(env)
				data, _ := json.Marshal(jsonOut{
					Backend:       cfg.Backend,
					Connections:   statuses,
					CustomSecrets: custom,
					Gateway:       gw,
					LLMSession:    llmcontext.IsLLMSession(env),
				})
				fmt.Fprintln(c.OutOrStdout(), string(data))
				return nil
			}

			printStatusDashboard(c, cfg.Backend, statuses, env)
			printCustomSecrets(c, custom)
			return nil
		},
	}
	cmd.Flags().String("namespace", "default", "vault namespace")
	cmd.Flags().Bool("test", false, "run health test for each connection")
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

// loadCustomSecretsForDisplay reads the custom-secret rules; they hold no value.
// A broken file is reported on stderr so the rest of the dashboard still renders.
func loadCustomSecretsForDisplay(c *cobra.Command, env llmcontext.Lookup) []customsecret.Secret {
	secrets, err := customsecret.Load(paths.CustomSecrets(env))
	if err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "warning: custom secrets unreadable: %v\n", err)
		return []customsecret.Secret{}
	}
	if secrets == nil {
		return []customsecret.Secret{}
	}
	return secrets
}

// printCustomSecrets lists custom secrets by name, hosts, injection kind and source.
func printCustomSecrets(c *cobra.Command, secrets []customsecret.Secret) {
	if len(secrets) == 0 {
		return
	}
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "\nCustom secrets\t\t\t\n")
	fmt.Fprintf(w, "  NAME\tSTATE\tHOSTS\tINJECTION\tSOURCE\n")
	for _, s := range secrets {
		v := s.Shown()
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", s.Name, s.State(), strings.Join(v.Hosts, ","), v.Kind(), v.Source())
	}
	w.Flush() //nolint:errcheck // output errors are non-critical here
}

// gatewayStatusInfo holds gateway running state for the dashboard.
type gatewayStatusInfo struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid,omitempty"`
	Address string `json:"address,omitempty"`
}

// detectGatewayStatus checks whether the gateway is running by reading the PID file.
func detectGatewayStatus(env llmcontext.Lookup) gatewayStatusInfo {
	pidPath := paths.GatewayPID(env)
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return gatewayStatusInfo{Running: false}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return gatewayStatusInfo{Running: false}
	}
	if _, running := gateway.IsRunning(pidPath); !running {
		return gatewayStatusInfo{Running: false}
	}
	return gatewayStatusInfo{Running: true, PID: pid, Address: ":7878"}
}

// relativeTime returns a human-readable relative time string ("2h ago", "never", etc.).
func relativeTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := time.Since(*t)
	if d < 0 {
		return "just now"
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// printStatusDashboard renders the system dashboard in human-readable form.
func printStatusDashboard(c *cobra.Command, backend string, statuses []connections.ConnectionStatus, env llmcontext.Lookup) {
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 3, ' ', 0)

	// Header section.
	vaultLine := fmt.Sprintf("backend=%s", backend)
	connCount := fmt.Sprintf("%d connections", len(statuses))

	gw := detectGatewayStatus(env)
	gatewayLine := "not running"
	if gw.Running {
		gatewayLine = fmt.Sprintf("running on %s", gw.Address)
	}

	isLLM := llmcontext.IsLLMSession(env)
	llmLine := "not detected"
	if isLLM {
		reasons := llmcontext.Reasons(env)
		llmLine = "active"
		if len(reasons) > 0 {
			llmLine += " — " + reasons[0]
		}
	}

	fmt.Fprintf(w, "Vault\t%s\t%s\n", vaultLine, connCount)
	fmt.Fprintf(w, "Gateway\t%s\t\n", gatewayLine)
	fmt.Fprintf(w, "LLM session\t%s\t\n", llmLine)
	fmt.Fprintf(w, "Last audit\t(see keylatch audit)\t\n")
	fmt.Fprintln(w)

	if len(statuses) == 0 {
		fmt.Fprintln(w, "No connections yet — run `keylatch connect <provider>` to add one.")
	} else {
		// Connections table.
		fmt.Fprintf(w, "Connections\t\t\t\n")
		fmt.Fprintf(w, "  PROVIDER\tACCOUNT\tSTATUS\tLAST USED\tLOCAL-ONLY\n")
		for _, s := range statuses {
			lastUsed := relativeTime(s.Connection.LastTested)
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
				s.Connection.Provider,
				s.Connection.Account,
				s.Connection.Status,
				lastUsed,
				formatLocalOnly(s.Connection.LocalOnly),
			)
		}
	}

	w.Flush() //nolint:errcheck // output errors are non-critical here
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "Run 'keylatch doctor' for deep diagnostics.")
}

// newDescribeCmd returns the `describe` command.
func newDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <connection-or-provider>",
		Short: "Describe a connection or provider template (no values)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			tmpl, masked, err := connections.Describe(ctx, args[0], store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			var conn *connections.Connection
			if lc, lcErr := connections.Load(ctx, "default", tmpl.Provider, store); lcErr == nil {
				conn = lc
			}

			useJSON, _ := c.Flags().GetBool("json")
			if useJSON {
				out := map[string]interface{}{
					"template":      tmpl,
					"masked_fields": masked,
				}
				if conn != nil {
					out["class"] = conn.Class
					out["local_only"] = conn.LocalOnly
				}
				data, _ := json.Marshal(out)
				fmt.Fprintln(c.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "Provider:     %s\n", tmpl.Provider)
			fmt.Fprintf(c.OutOrStdout(), "Display Name: %s\n", tmpl.DisplayName)
			fmt.Fprintf(c.OutOrStdout(), "Category:     %s\n", tmpl.Category)
			fmt.Fprintf(c.OutOrStdout(), "Auth Flow:    %s\n", tmpl.AuthFlow)
			fmt.Fprintf(c.OutOrStdout(), "Runtime:      %s\n", tmpl.RuntimeSupport.Preferred)
			if conn != nil && conn.Class != "" {
				fmt.Fprintf(c.OutOrStdout(), "Class:        %s\n", conn.Class)
			}
			fmt.Fprintln(c.OutOrStdout(), "\nSecret Fields (masked):")
			for name, val := range masked {
				if conn != nil && conn.LocalOnly[name] != "" {
					fmt.Fprintf(c.OutOrStdout(), "  %s: %s (local-only: %s)\n", name, val, conn.LocalOnly[name])
					continue
				}
				fmt.Fprintf(c.OutOrStdout(), "  %s: %s\n", name, val)
			}
			fmt.Fprintln(c.OutOrStdout(), "\nCapabilities:")
			for _, cap := range tmpl.Capabilities {
				fmt.Fprintf(c.OutOrStdout(), "  - %s: %s\n", cap.Name, cap.Description)
			}
			return nil
		},
	}
}
