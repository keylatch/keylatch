// Package cli implements the keylatch command-line interface.
// help_topics.go registers the `help-topic` command and its topic subcommands.
// Each topic prints a concise inline reference and a link to the full docs.
package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

// newHelpTopicsCmd returns the top-level `help-topic` command with all topic
// subcommands attached. Register it via addHelpTopics(root).
//
// Usage:
//
//	keylatch help-topic                  — list all topics
//	keylatch help-topic modes            — five-mode reference table
//	keylatch help-topic backends         — backend capabilities matrix
//	keylatch help-topic providers        — registered providers with category and mode
//	keylatch help-topic security         — six-line security model summary
//	keylatch help-topic errors           — KL-XXXX error code namespace overview
//	keylatch help-topic wizard           — link to browser dashboard
//	keylatch help-topic troubleshooting  — top issues and error-code index
func newHelpTopicsCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "help-topic [topic]",
		Short: "Print inline reference for a specific topic",
		Long: `Print an inline reference page for a topic and exit 0.

Available topics:

  modes            Five-mode runtime architecture
  backends         Backend capabilities matrix
  providers        Registered providers with category and preferred mode
  security         Six-line security model summary
  errors           KL-XXXX error code namespace overview
  wizard           Link to the browser dashboard
  troubleshooting  Top issues, error-code index, and keylatch doctor`,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return c.Help()
			}
			return fmt.Errorf("unknown topic %q — run 'keylatch help-topic' to list topics", args[0])
		},
	}

	parent.AddCommand(newHelpTopicModesCmd())
	parent.AddCommand(newHelpTopicBackendsCmd())
	parent.AddCommand(newHelpTopicProvidersCmd())
	parent.AddCommand(newHelpTopicSecurityCmd())
	parent.AddCommand(newHelpTopicErrorsCmd())
	parent.AddCommand(newHelpTopicWizardCmd())
	parent.AddCommand(newHelpTopicTroubleshootingCmd())

	return parent
}

// addHelpTopics registers the help-topic command on root under the "support" group.
// Call this from NewRootCommand / Register.
func addHelpTopics(root *cobra.Command) {
	root.AddGroup(&cobra.Group{ID: "support", Title: "Help & Reference"})
	addCmd(root, newHelpTopicsCmd(), "support")
}

// newHelpTopicModesCmd prints the five-mode runtime table.
func newHelpTopicModesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modes",
		Short: "Five-mode runtime architecture reference",
		RunE: func(c *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Runtime modes (keylatch run --runtime <mode>)")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Mode\tRelease\tGateway required\tLLM session\tDescription")
			fmt.Fprintln(w, "----\t-------\t----------------\t-----------\t-----------")
			fmt.Fprintln(w, "gateway_typed\t0.1.0\tYes\tAllowed\tTyped gateway — strongest isolation (default)")
			fmt.Fprintln(w, "gateway_sdk\t0.1.0\tYes\tAllowed\tOpenAI-compatible SDK proxy via gateway")
			fmt.Fprintln(w, "direct_brokered\t0.1.0\tNo\tAllowed\tEphemeral broker tokens — no gateway needed")
			fmt.Fprintln(w, "gateway_proxy\t0.1.0\tYes\tAllowed\tHTTPS MITM proxy rewriting Authorization headers")
			fmt.Fprintln(w, "direct_classic\t0.1.0\tNo\tApprovalJWT req.\tRaw env injection — requires JWT in LLM sessions")
			fmt.Fprintln(w, "direct_classic_sandboxed\t0.2.0\tNo\tApprovalJWT req.\tSame as direct_classic + bwrap/sandbox-exec (planned)")
			_ = w.Flush()
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Trust hierarchy (highest to lowest):")
			fmt.Fprintln(c.OutOrStdout(), "  gateway_typed > gateway_sdk > direct_brokered > gateway_proxy > direct_classic")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Full explainer: docs/architecture/modes.md")
			fmt.Fprintln(c.OutOrStdout(), "Diagnose a provider: keylatch runtime doctor <provider>")
			return nil
		},
	}
}

// newHelpTopicBackendsCmd prints the backend capabilities matrix.
func newHelpTopicBackendsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backends",
		Short: "Backend capabilities matrix",
		RunE: func(c *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Credential store backends")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Backend\tKey\tPlatform\tEncrypted\tBiometric\tTeam sharing\tOffline")
			fmt.Fprintln(w, "-------\t---\t--------\t---------\t---------\t------------\t-------")
			fmt.Fprintln(w, "Encrypted file\tfile\tAll\tYes (XChaCha20)\tNo\tNo\tYes")
			fmt.Fprintln(w, "macOS Keychain\tkeychain\tmacOS\tYes (system)\tYes (Touch ID)\tNo\tYes")
			fmt.Fprintln(w, "1Password\top\tAll\tYes\tYes\tYes\tNo")
			fmt.Fprintln(w, "Bitwarden\tbw\tAll\tYes\tNo\tYes\tPartial")
			fmt.Fprintln(w, "ProtonPass\tprotonpass\tAll\tYes\tNo\tYes\tNo")
			fmt.Fprintln(w, "Keeper\tkeeper\tAll\tYes\tNo\tYes\tNo")
			fmt.Fprintln(w, "LastPass\tlastpass\tAll\tYes\tNo\tYes\tNo")
			fmt.Fprintln(w, "HashiCorp Vault\tvault\tAll\tYes\tNo\tYes\tNo")
			fmt.Fprintln(w, "AWS Secrets Manager\tawssm\tAll\tYes (cloud)\tNo\tYes\tNo")
			fmt.Fprintln(w, "1Password Connect\topconnect\tAll\tYes\tNo\tYes\tNo")
			fmt.Fprintln(w, "GCP Secret Manager\tgcpsm\tAll\tYes (cloud)\tNo\tYes\tNo")
			fmt.Fprintln(w, "Azure Key Vault\tazurekv\tAll\tYes (cloud)\tNo\tYes\tNo")
			fmt.Fprintln(w, "Doppler\tdoppler\tAll\tYes (cloud)\tNo\tYes\tNo")
			fmt.Fprintln(w, "Infisical\tinfisical\tAll\tYes (cloud)\tNo\tYes\tNo")
			_ = w.Flush()
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Set backend: keylatch config set backend <key>")
			fmt.Fprintln(c.OutOrStdout(), "Full reference: docs/backends/index.md")
			return nil
		},
	}
}

// newHelpTopicProvidersCmd prints all registered providers with category and preferred mode.
func newHelpTopicProvidersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "providers",
		Short: "List registered providers with category and preferred runtime mode",
		RunE: func(c *cobra.Command, _ []string) error {
			templates := registry.List()
			if len(templates) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No providers registered. Run 'keylatch bootstrap' first.")
				return nil
			}

			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Provider\tDisplay Name\tCategory\tPreferred mode\tTrust")
			fmt.Fprintln(w, "--------\t------------\t--------\t--------------\t-----")
			for _, t := range templates {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
					t.Provider,
					t.DisplayName,
					t.Category,
					t.RuntimeSupport.Preferred,
					t.TrustLevel,
				)
			}
			_ = w.Flush()
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Connect: keylatch connect <provider> <field> <value>")
			fmt.Fprintln(c.OutOrStdout(), "Full catalog: docs/providers/index.md")
			return nil
		},
	}
}

// newHelpTopicSecurityCmd prints a six-line security model summary.
func newHelpTopicSecurityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "security",
		Short: "Security model summary",
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), "Keylatch security model")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "1. LLM session detection — blocks keylatch get (exit 2) and restricts the UI to")
			fmt.Fprintln(c.OutOrStdout(), "   status-only scope when CLAUDE_CODE, CODEX_ENV, CREDENTIALS_LLM_SESSION,")
			fmt.Fprintln(c.OutOrStdout(), "   CURSOR_SESSION, AIDER_SESSION, GEMINI_SESSION, or OPENCODE_SESSION is set.")
			fmt.Fprintln(c.OutOrStdout(), "2. Runtime mode guard — enforces a 30-cell policy matrix (IsLLMSession x")
			fmt.Fprintln(c.OutOrStdout(), "   RuntimeMode x ApprovalJWT). direct_classic requires a hardware-backed JWT in")
			fmt.Fprintln(c.OutOrStdout(), "   LLM sessions; gateway modes are always allowed.")
			fmt.Fprintln(c.OutOrStdout(), "3. Gateway isolation — agent processes receive only a short-lived session token")
			fmt.Fprintln(c.OutOrStdout(), "   and a gateway URL. Provider keys never return to the agent process.")
			fmt.Fprintln(c.OutOrStdout(), "4. Encrypted at rest — all backends encrypt values before write. No plaintext")
			fmt.Fprintln(c.OutOrStdout(), "   on disk.")
			fmt.Fprintln(c.OutOrStdout(), "5. Tamper-evident audit log — HMAC-chained, value-free, written to")
			fmt.Fprintln(c.OutOrStdout(), "   ~/.keylatch/audit.log (mode 0600).")
			fmt.Fprintln(c.OutOrStdout(), "6. Canary leak detection — sentinel values injected at test time; CI static")
			fmt.Fprintln(c.OutOrStdout(), "   grep catches any canary escaping into production code.")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Full model: docs/security.md")
			fmt.Fprintln(c.OutOrStdout(), "Vulnerability disclosure: SECURITY.md")
			return nil
		},
	}
}

// newHelpTopicErrorsCmd prints the KL-XXXX error code namespace overview.
func newHelpTopicErrorsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "errors",
		Short: "Exit code and error code namespace overview",
		RunE: func(c *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Exit codes")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Code\tName\tMeaning")
			fmt.Fprintln(w, "----\t----\t-------")
			fmt.Fprintln(w, "0\tOK\tSuccess")
			fmt.Fprintln(w, "1\tUserError\tInvalid input or configuration")
			fmt.Fprintln(w, "2\tSecurityBlock\tBlocked by LLM-session guard or missing ApprovalJWT")
			fmt.Fprintln(w, "3\tMissing\tResource not found")
			fmt.Fprintln(w, "4\tBackendUnavailable\tCredential backend unreachable or unauthenticated")
			fmt.Fprintln(w, "5\tOperationFailed\tInternal or unrecoverable error")
			_ = w.Flush()
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(w, "KL-XXXX error code ranges")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Range\tArea\tExamples")
			fmt.Fprintln(w, "-----\t----\t--------")
			fmt.Fprintln(w, "KL-0001–0099\tCore / config\tBootstrap failures, config parse errors")
			fmt.Fprintln(w, "KL-0100–0199\tBackend\tBackend unavailable, encrypt/decrypt errors")
			fmt.Fprintln(w, "KL-0200–0299\tRegistry\tProvider not found, schema validation failures")
			fmt.Fprintln(w, "KL-0300–0399\tRuntime / runner\tMode unavailable, command not in allowlist")
			fmt.Fprintln(w, "KL-0400–0499\tGateway\tGateway not running, token expired, SSRF blocked")
			fmt.Fprintln(w, "KL-0500–0599\tSecurity\tLLM session block, ApprovalJWT missing/invalid")
			fmt.Fprintln(w, "KL-0600–0699\tAudit\tAudit log write failure, chain verification error")
			_ = w.Flush()
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Structured error codes are stamped on errors returned by internal packages.")
			fmt.Fprintln(c.OutOrStdout(), "Use --json to see the code field in machine-readable output.")
			return nil
		},
	}
}

// newHelpTopicWizardCmd prints the link to the browser dashboard.
func newHelpTopicWizardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wizard",
		Short: "Open the browser dashboard",
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), "Run 'keylatch ui' to open the browser dashboard at 127.0.0.1:7890")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "The browser UI provides:")
			fmt.Fprintln(c.OutOrStdout(), "  - Connection management (add, remove, test providers)")
			fmt.Fprintln(c.OutOrStdout(), "  - Approval inbox (approve or deny pending runtime requests)")
			fmt.Fprintln(c.OutOrStdout(), "  - Agent profile setup (write Claude Code / Codex config snippets)")
			fmt.Fprintln(c.OutOrStdout(), "  - Runtime receipts (value-free audit of recent run invocations)")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Options:")
			fmt.Fprintln(c.OutOrStdout(), "  keylatch ui --demo      # Explore with stub data (no real credentials)")
			fmt.Fprintln(c.OutOrStdout(), "  keylatch ui --no-open   # Print URL without opening the browser")
			return nil
		},
	}
}

// newHelpTopicTroubleshootingCmd prints the top 10 user issues and KL-error-code index.
func newHelpTopicTroubleshootingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "troubleshooting",
		Short: "Top issues, error-code index, and keylatch doctor",
		RunE: func(c *cobra.Command, _ []string) error {
			out := c.OutOrStdout()
			fmt.Fprintln(out, "Keylatch — top troubleshooting issues")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "1.  Daemon not running")
			fmt.Fprintln(out, "      Symptom: 'connection refused' or 'keylatch run' hangs.")
			fmt.Fprintln(out, "      Fix:     run 'keylatch gateway up' then retry.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "2.  Backend unavailable (KL-0100–0199)")
			fmt.Fprintln(out, "      Symptom: exit 4 (BackendUnavailable).")
			fmt.Fprintln(out, "      Fix:     run 'keylatch doctor' — check backend row.")
			fmt.Fprintln(out, "               macOS: unlock Keychain with Touch ID first.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "3.  LLM session block (KL-0500–0599)")
			fmt.Fprintln(out, "      Symptom: exit 2 (SecurityBlock); 'blocked in LLM session'.")
			fmt.Fprintln(out, "      Fix:     use 'keylatch run' instead of 'keylatch get' or 'keylatch inject'.")
			fmt.Fprintln(out, "               For direct_classic mode: provide --approval-jwt.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "4.  ApprovalJWT missing or invalid")
			fmt.Fprintln(out, "      Symptom: exit 2; 'ApprovalJWT required for direct_classic'.")
			fmt.Fprintln(out, "      Fix:     approve the request in 'keylatch ui' (approval inbox),")
			fmt.Fprintln(out, "               then re-run with the JWT printed by the approval step.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "5.  Gateway port conflict")
			fmt.Fprintln(out, "      Symptom: 'bind: address already in use' on port 7890 or 7878.")
			fmt.Fprintln(out, "      Fix:     set KEYLATCH_GATEWAY_ADDR=127.0.0.1:<free-port> in env.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "6.  Bootstrap fails (KL-0001–0099)")
			fmt.Fprintln(out, "      Symptom: 'bootstrap: ...' error on first run.")
			fmt.Fprintln(out, "      Fix:     run 'keylatch bootstrap --dry-run' to diagnose,")
			fmt.Fprintln(out, "               then 'keylatch bootstrap' to repair.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "7.  No providers registered (KL-0200–0299)")
			fmt.Fprintln(out, "      Symptom: 'no providers registered'; empty 'keylatch list'.")
			fmt.Fprintln(out, "      Fix:     run 'keylatch bootstrap' to load default templates.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "8.  Audit log missing or unwritable (KL-0600–0699)")
			fmt.Fprintln(out, "      Symptom: 'audit: write failure'; log not at ~/.keylatch/audit.log.")
			fmt.Fprintln(out, "      Fix:     check permissions: chmod 0600 ~/.keylatch/audit.log")
			fmt.Fprintln(out, "               or set KEYLATCH_AUDIT_PATH to a writable path.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "9.  Wizard not completing")
			fmt.Fprintln(out, "      Symptom: 'keylatch ui' shows wizard loop; readiness check fails.")
			fmt.Fprintln(out, "      Fix:     open 127.0.0.1:7890 in a browser and complete each step.")
			fmt.Fprintln(out, "               Set wizard.completed: true in keylatch.yaml to skip.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "10. Spectral lint failure (OpenAPI spec)")
			fmt.Fprintln(out, "      Symptom: CI openapi-lint job fails.")
			fmt.Fprintln(out, "      Fix:     run 'npx @stoplight/spectral-cli lint docs/api/openapi.yaml'")
			fmt.Fprintln(out, "               locally. Fix the reported rule violations.")
			fmt.Fprintln(out)

			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KL-XXXX error code ranges")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Range\tArea\tExamples")
			fmt.Fprintln(w, "-----\t----\t--------")
			fmt.Fprintln(w, "KL-0001–0099\tCore / config\tBootstrap failures, config parse errors")
			fmt.Fprintln(w, "KL-0100–0199\tBackend\tBackend unavailable, encrypt/decrypt errors")
			fmt.Fprintln(w, "KL-0200–0299\tRegistry\tProvider not found, schema validation failures")
			fmt.Fprintln(w, "KL-0300–0399\tRuntime / runner\tMode unavailable, command not in allowlist")
			fmt.Fprintln(w, "KL-0400–0499\tGateway\tGateway not running, token expired, SSRF blocked")
			fmt.Fprintln(w, "KL-0500–0599\tSecurity\tLLM session block, ApprovalJWT missing/invalid")
			fmt.Fprintln(w, "KL-0600–0699\tAudit\tAudit log write failure, chain verification error")
			_ = w.Flush()

			fmt.Fprintln(out)
			fmt.Fprintln(out, "Full troubleshooting guide: docs/troubleshooting.md")
			fmt.Fprintln(out, "Run diagnostics:            keylatch doctor")
			return nil
		},
	}
}
