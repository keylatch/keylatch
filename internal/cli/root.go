// Package cli implements the keylatch command-line interface.
// All cobra commands and their handlers are defined in this package.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/all"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/canary"
	cmdregistry "github.com/keylatch/keylatch/internal/cmd/regvalidate"
	cmdtrust "github.com/keylatch/keylatch/internal/cmd/trust"
	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	_ "github.com/keylatch/keylatch/internal/trust/all"
	"github.com/keylatch/keylatch/internal/version"
	"github.com/spf13/cobra"
)

// DoctorHint is the hint printed when any non-trivial command exits non-zero.
// §2.5: exposed so cmd/keylatch/main.go can print it after Execute returns an error.
const DoctorHint = "Run `keylatch doctor` for a health check, or visit keylatch.dev/troubleshoot"

// IsDoctorHintSuppressed returns true for commands where a doctor hint is
// unhelpful — --help, --version, completion, and the doctor command itself.
// Exported so cmd/keylatch/main.go can use it.
func IsDoctorHintSuppressed(c *cobra.Command) bool {
	name := c.Name()
	switch name {
	case "doctor", "help", "completion", "__complete", "__completeNoDesc":
		return true
	}
	// Suppress if --help or --version was requested.
	if h, _ := c.Flags().GetBool("help"); h {
		return true
	}
	if v, _ := c.Root().Flags().GetBool("version"); v {
		return true
	}
	return false
}

// NewRootCommand returns the root Cobra command for the keylatch CLI.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "keylatch",
		Short: "Keylatch — zero-trust credential vault CLI",
		Long:  "Keylatch manages credentials with LLM-session blocking and gateway-aware runtime modes.",
		// Version is used by cobra to respond to --version; the template below
		// formats the output as a short one-liner (e.g. "keylatch v1.0.0-dev").
		Version: version.String(),
		// PersistentPreRunE handles --version and registry initialisation before
		// any subcommand runs.
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			// Configure slog level from --log-level flag.
			logLevel, _ := c.Root().PersistentFlags().GetString("log-level")
			var level slog.Level
			switch strings.ToLower(logLevel) {
			case "debug":
				level = slog.LevelDebug
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				level = slog.LevelInfo
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

			ver, _ := c.Root().Flags().GetBool("version")
			if ver {
				jsonOut, _ := c.Root().Flags().GetBool("json")
				if jsonOut {
					b, _ := json.Marshal(version.JSON())
					fmt.Fprintln(c.OutOrStdout(), string(b))
				} else {
					fmt.Fprintln(c.OutOrStdout(), version.String())
				}
				os.Exit(exitcode.OK)
				return nil
			}

			// Check for backend registration failures from init() side-effects.
			if errs := backend.RegistrationErrors(); len(errs) > 0 {
				for _, e := range errs {
					slog.Error("backend registration failed", "error", e)
				}
				return fmt.Errorf("one or more backend registrations failed at startup")
			}

			// Initialise the provider registry from embedded + local + community
			// YAML templates. This must run before any subcommand that reads the registry.
			if err := registry.InitFromConfig(c.Context(), llmcontext.DefaultLookup); err != nil {
				slog.Error("registry init failed", "error", err)
				os.Exit(exitcode.OperationFailed)
			}
			return nil
		},
	}
	// SilenceErrors suppresses cobra's default "Error: ..." line on stderr so
	// main.go can print the doctor hint before exiting. SilenceUsage prevents
	// the full usage block from printing on every flag-parse error.
	root.SilenceErrors = true
	root.SilenceUsage = true
	// Override cobra's default "{{.Name}} version {{.Version}}" template so that
	// --version prints the full version string (which already includes "keylatch").
	root.SetVersionTemplate("{{.Version}}\n")

	root.Flags().Bool("version", false, "print version information and exit")
	root.PersistentFlags().Bool("json", false, "output in JSON format")
	root.PersistentFlags().Bool("quiet", false, "suppress non-essential output")
	root.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")

	// P1.1: Add help groups for user-journey-oriented help output.
	root.AddGroup(&cobra.Group{ID: "start", Title: "Getting Started"})
	root.AddGroup(&cobra.Group{ID: "daily", Title: "Daily Use"})
	root.AddGroup(&cobra.Group{ID: "gateway", Title: "Gateway"})
	root.AddGroup(&cobra.Group{ID: "team", Title: "Team"})
	root.AddGroup(&cobra.Group{ID: "advanced", Title: "Advanced"})

	Register(root)
	return root
}

// addCmd is a helper that adds a command to root with a groupID set.
func addCmd(root *cobra.Command, cmd *cobra.Command, groupID string) {
	cmd.GroupID = groupID
	root.AddCommand(cmd)
}

// Register attaches all subcommands to root with group assignments.
// P0.4: stub commands are Hidden=true so they don't clutter --help.
// P1.1: commands are grouped by user journey.
func Register(root *cobra.Command) {
	// --- Getting Started ---
	addCmd(root, newSetupCmd(), "start")
	addCmd(root, newInitCmd(), "start")
	addCmd(root, newPhase3ConnectCmd(), "start")
	addCmd(root, newPhase3AgentCmd(), "start")
	addCmd(root, newDoctorCmdImpl(), "start")
	addCmd(root, newUICmd(), "start")
	addCmd(root, newBootstrapCmd(), "start")
	addCmd(root, newInstallGuardCmd(), "start")
	addHelpTopics(root)

	// --- Daily Use ---
	addCmd(root, newGetCmd(), "daily")
	addCmd(root, newGetMaskedCmd(), "daily")
	addCmd(root, newListCmdImpl(), "daily")
	addCmd(root, newPhase3StatusCmd(), "daily")
	addCmd(root, newRunCmd(), "daily")
	addCmd(root, newShareCmd(), "daily")
	addCmd(root, newAllowCmd(), "daily")
	addCmd(root, newDisconnectCmd(), "daily")
	// keylatch inject was removed in v1.0.0. Running it returns cobra's "unknown command" error.
	addCmd(root, newPhase3TestCmd(), "daily")
	addCmd(root, newPhase3DescribeCmd(), "daily")
	addCmd(root, newModesCmd(), "daily")

	// --- Gateway ---
	addCmd(root, newGatewayCmd(), "gateway")

	// --- Team ---
	addCmd(root, newTeamCmd(), "team")

	// --- Advanced (everything else) ---
	addCmd(root, newPolicyCmd(), "advanced")
	addCmd(root, newGrantCmd(), "advanced")
	addCmd(root, newActorsCmd(), "advanced")
	addCmd(root, newAuditCmd(), "advanced")
	addCmd(root, newSecurityCmd(), "advanced")
	addCmd(root, newVerifyCmd(), "advanced")
	addCmd(root, newPhase3ValidateCmd(), "advanced")
	addCmd(root, newBackendCmd(), "advanced")
	addCmd(root, newCompletionCmd(root), "advanced")
	addCmd(root, newConfigCmd(), "advanced")
	addCmd(root, newCryptoCmd(), "advanced")
	addCmd(root, newHealthCmd(), "advanced")
	addCmd(root, newMigrateCmd(), "advanced")
	addCmd(root, newProjectsCmd(), "advanced")
	addCmd(root, newReceiptsCmd(), "advanced")
	addCmd(root, newRegistryCmd(), "advanced")
	addCmd(root, newRollbackCmd(), "advanced")
	addCmd(root, newRulesCmd(), "advanced")
	addCmd(root, newSessionsCmd(), "advanced")
	addCmd(root, newSetCmd(), "advanced")
	// Trust and shared-secret commands are now registered from internal/cmd/trust.
	cmdtrust.RegisterCommands(root, "advanced")
	addCmd(root, newVersionsCmd(), "advanced")
	addCmd(root, newDestroyVersionCmd(), "advanced")
	addCmd(root, newPhase4CheckExpiryCmd(), "advanced")
	addCmd(root, newKeyringCmd(), "advanced")
	addCmd(root, newPhase3MCPCmd(), "advanced")
	addCmd(root, newTokenCmd(), "advanced")

	// Phase 1: keychain lifecycle commands (advanced).
	RegisterKeychainCommands(root)
	// Phase 2: 1Password and Bitwarden commands (advanced).
	RegisterOPCommands(root)
	RegisterBWCommands(root)

	// `connections` redirects to `list` — hide from help.
	connectionsCmd := newConnectionsCmd()
	connectionsCmd.Hidden = true
	root.AddCommand(connectionsCmd)

	// recipes stub — hide from help.
	recipesCmd := newUIRecipesCmd()
	recipesCmd.Hidden = true
	root.AddCommand(recipesCmd)

	// Experimental command group — always visible; lists gated commands and
	// prints enable instructions. When KEYLATCH_EXPERIMENTAL=1, the gated
	// commands are also added to this group as aliases.
	experimentalGroup := newExperimentalCmd()
	addCmd(root, experimentalGroup, "advanced")

	// Epics 19-22: proxy, sandbox, call, broker graduated from experimental.
	// Registered unconditionally so shell completion and invocation work without
	// KEYLATCH_EXPERIMENTAL=1.
	root.AddCommand(newProxyCmdFull())
	root.AddCommand(newSandboxCmd())
	root.AddCommand(newPhase3CallCmd())
	root.AddCommand(newBrokerCmd())

	// Epic 23: approve and deny graduated to production — registered unconditionally.
	// LLM session guard is enforced at runtime by the commands themselves.
	root.AddCommand(newApproveCmd())
	root.AddCommand(newDenyCmd())
	if isExperimentalEnabled() {
		registerExperimentalAliases(experimentalGroup, root)
	}

	// `paths` and `env` informational commands (advanced).
	addCmd(root, newPathsCmd(), "advanced")
	addCmd(root, newEnvCmd(), "advanced")

	// T-12-02: backup command.
	addCmd(root, newBackupCmd(), "advanced")

	// `verify` — cosign signature verification.
	addCmd(root, newVerifyCmd(), "advanced")

	// runtime group is now implemented.
	addCmd(root, newRuntimeCmd(), "advanced")
}

// newRegistryCmd returns the `registry` subcommand group.
func newRegistryCmd() *cobra.Command {
	reg := &cobra.Command{
		Use:   "registry",
		Short: "Manage and inspect the provider registry",
	}
	reg.AddCommand(cmdregistry.NewValidateCmd())
	reg.AddCommand(newRegistryListCmd())
	reg.AddCommand(newRegistryDescribeCmd())
	reg.AddCommand(newRegistryReloadCmd())
	reg.AddCommand(newRegistryScaffoldCmd())
	return reg
}

// newRuntimeCmd returns the `runtime` subcommand group.
func newRuntimeCmd() *cobra.Command {
	runtime := &cobra.Command{
		Use:   "runtime",
		Short: "Manage and inspect runtime mode configuration",
	}
	runtime.AddCommand(newRuntimeDoctorCmd())
	return runtime
}

// runtimeModeStatus describes a single mode's availability for a provider.
type runtimeModeStatus struct {
	Mode      string `json:"mode"`
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// runtimeDoctorReport is the output of `runtime doctor`.
type runtimeDoctorReport struct {
	Provider string              `json:"provider"`
	Modes    []runtimeModeStatus `json:"modes"`
}

// newRuntimeDoctorCmd returns the `runtime doctor` subcommand.
func newRuntimeDoctorCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "doctor <provider>",
		Short: "Diagnose runtime mode availability for a provider",
		Long: `Diagnose which runtime modes are available for a provider.

Reports which modes are declared in the provider template (runtime_support),
which are available given current system state (bwrap? gateway running?),
and why unavailable modes cannot be used.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup

			provider := args[0]
			report := buildRuntimeDoctorReport(env, provider)

			if useJSON {
				b, _ := json.MarshalIndent(report, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "runtime doctor — provider: %s\n\n", report.Provider)
			for _, m := range report.Modes {
				status := "ok  "
				if !m.Available {
					status = "FAIL"
				}
				fmt.Fprintf(c.OutOrStdout(), "  [%s] %s: %s\n", status, m.Mode, m.Reason)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}

// buildRuntimeDoctorReport checks each runtime mode for a provider.
func buildRuntimeDoctorReport(env llmcontext.Lookup, provider string) runtimeDoctorReport {
	report := runtimeDoctorReport{Provider: provider}

	if provider == "" {
		return report
	}

	// Look up provider template.
	tmpl, err := registry.Get(provider)
	if err != nil {
		report.Modes = []runtimeModeStatus{
			{Mode: "all", Available: false, Reason: "provider not found: run 'keylatch list' to see available providers"},
		}
		return report
	}

	// Build supported set.
	supportedModes := make(map[string]bool)
	for _, m := range tmpl.RuntimeSupport.Supported {
		supportedModes[string(m)] = true
	}
	preferredMode := string(tmpl.RuntimeSupport.Preferred)

	// Check gateway liveness.
	gatewayRunning := false
	pidPath := paths.GatewayPID(env)
	if _, running := gateway.IsRunning(pidPath); running {
		gatewayRunning = true
	}

	// v1.0.0 mode set (EPIC-24: direct_classic_sandboxed reinstated).
	allModes := []string{"gateway_typed", "gateway_sdk", "direct_brokered", "gateway_proxy", "direct_classic_sandboxed"}
	for _, m := range allModes {
		status := runtimeModeStatus{Mode: m}

		inSupported := supportedModes[m]
		preferred := m == preferredMode

		var reason string
		switch {
		case !inSupported:
			reason = fmt.Sprintf("not in %s runtime_support", provider)
			status.Available = false
		case m == "gateway_typed" || m == "gateway_sdk" || m == "gateway_proxy":
			if gatewayRunning {
				reason = "gateway running"
				if preferred {
					reason += " (preferred mode)"
				}
				status.Available = true
			} else {
				reason = "gateway not running: run 'keylatch gateway up'"
				status.Available = false
			}
		case m == "direct_brokered":
			if preferred {
				reason = "preferred mode — broker strategy available"
			} else {
				reason = "supported"
			}
			status.Available = true
		case m == "direct_classic_sandboxed":
			// EPIC-24: sandbox availability depends on platform primitive.
			sandboxAvail, sandboxReason, _ := sandboxModeAvailability()
			if sandboxAvail {
				reason = "sandbox primitive available: " + sandboxReason
				if preferred {
					reason += " (preferred mode)"
				}
				status.Available = true
			} else {
				reason = "sandbox not available: " + sandboxReason + " — run 'keylatch sandbox doctor'"
				status.Available = false
			}
		default:
			reason = "unknown mode"
			status.Available = false
		}

		status.Reason = reason
		report.Modes = append(report.Modes, status)
	}

	return report
}

// newGetCmd returns the `get` subcommand wrapped with GuardLLMSession.
// S0-5: `get` is value-bearing — it IS guarded.
// S0-4: blocked in LLM session with exit code SecurityBlock.
func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <service> <key>",
		Short: "Retrieve a credential value",
	}
	cmd.Flags().Bool("masked", false, "return masked value (safe in LLM sessions)")

	// notImplementedGetHandler is value-bearing but not yet implemented.
	// GuardLLMSession will block in LLM sessions (exit 2).
	// Outside LLM sessions it exits OperationFailed (5) via os.Exit.
	notImpl := Handler(func(_ context.Context, _ HandlerArgs) (Result, error) {
		os.Exit(exitcode.OperationFailed)
		return Result{}, nil // unreachable
	})
	vbh := AsValueBearing(notImpl)

	cmd.RunE = func(c *cobra.Command, args []string) error {
		masked, _ := c.Flags().GetBool("masked")
		if masked {
			// --masked is NOT guarded — it never outputs raw credentials.
			// S0-5: get --masked is a safe path.
			stdout := c.OutOrStdout()
			if len(args) >= 2 {
				fmt.Fprintf(stdout, "%s.%s = ****\n", args[0], args[1])
			} else {
				fmt.Fprintf(stdout, "**** = ****\n")
			}
			return nil
		}

		// M2: raw-credential-path corroboration (fail closed). `get`
		// (non-masked) always returns a raw credential value, so
		// rawCredentialExposure is unconditionally true here — this applies
		// to EVERY session, including one with no LLM signals at all
		// (SignalNone), which is the spoof-to-human case this check exists
		// to close. Gateway/proxy `run` is the only path left unaffected —
		// see RequireVerifiedSession for the full rationale and the escape
		// hatch (env var or config field).
		env := llmcontext.DefaultLookup
		if verErr := RequireVerifiedSession(env, true, configAllowsUnverifiedSession(env)); verErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "%v\n", verErr)
			os.Exit(exitcode.SecurityBlock)
		}

		hArgs := handlerArgsFromCmd(c, args)
		res, err := vbh.Invoke(c.Context(), hArgs)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}
		return nil
	}
	return cmd
}

// newGetMaskedCmd returns the `get-masked` subcommand — NOT guarded.
// S0-5: get-masked is a safe path.
func newGetMaskedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get-masked <service> <key>",
		Short: "Retrieve a masked credential (safe in LLM sessions)",
		RunE: func(c *cobra.Command, args []string) error {
			stdout := c.OutOrStdout()
			if len(args) >= 2 {
				fmt.Fprintf(stdout, "%s.%s = ****\n", args[0], args[1])
			} else {
				fmt.Fprintf(stdout, "**** = ****\n")
			}
			return nil
		},
	}
}

// newRunCmd returns the `run` subcommand with --runtime and --approval-jwt flags.
// S0-5: `run` is NOT value-bearing — not wrapped by GuardLLMSession.
// GuardRuntime enforces mode restrictions for LLM sessions.
// P1.2: actionable allowlist error with --allow flag.
// P1.4: success/failure summary printed to stderr after run.
func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <connection> -- <command>",
		Short: "Run a command with injected credentials",
		RunE: func(c *cobra.Command, args []string) error {
			mode := runtime.RuntimeMode(c.Flag("runtime").Value.String())
			modeFlag, _ := c.Flags().GetString("mode")
			approvalJWT := c.Flag("approval-jwt").Value.String()
			rawAllows, _ := c.Flags().GetStringArray("allow")
			var stderrBuf bytes.Buffer

			// EPIC-11 first-run guards — sequential, fail-fast checks before any
			// backend, vault, or runtime calls.
			//
			// Order: (1) mode validation → (2) bootstrap → (3) connection.
			// Mode validation runs first because it is pure/stateless and the
			// E2E tests expect removed-mode errors to take priority (exit 5).

			// Guard 1 (mode): validate that the requested runtime mode is available.
			// This runs first so removed-mode errors take priority over bootstrap
			// errors — the mode check is stateless and has no filesystem dependency.
			if hint, removed := runtime.IsRemovedMode(string(mode)); removed {
				cliErr := NewRuntimeNotAvailable("runtime mode %q has been removed: %s", mode, hint)
				fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
				os.Exit(exitcode.RuntimeNotAvailable)
			}

			// T-09-01: --dry-run mode must bypass all infrastructure guards because it
			// never decrypts credentials and must work on machines that have not yet
			// been bootstrapped (e.g. CI canary tests, operator previews).
			{
				dryRunEarly, _ := c.Flags().GetBool("dry-run")
				jsonOutEarly, _ := c.Flags().GetBool("json")
				if dryRunEarly {
					connName, cmd, pErr := parseRunArgs(args)
					if pErr != nil {
						fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", pErr)
						os.Exit(exitcode.UserError)
					}
					if connName == "" {
						fmt.Fprintln(c.ErrOrStderr(), "keylatch run: missing <connection> argument")
						os.Exit(exitcode.UserError)
					}
					if len(cmd) == 0 {
						fmt.Fprintln(c.ErrOrStderr(), "keylatch run: missing <command> after --")
						os.Exit(exitcode.UserError)
					}
					runDryRun(c, connName, cmd, mode, modeFlag, approvalJWT, jsonOutEarly)
					return nil
				}
			}

			// Guard 1b (M2): raw-credential-path corroboration (fail closed).
			// Skipped for --dry-run above (never decrypts a credential).
			// rawCredentialExposure is true only for direct/brokered runtime
			// modes (runtime.IsRawCredentialMode) — the modes that inject the
			// actual secret into the child env. Gateway/proxy modes never
			// expose a raw secret (child gets a scoped session token only),
			// so this is a no-op for them regardless of session verdict. See
			// RequireVerifiedSession for the full rationale and the escape
			// hatch (KEYLATCH_ALLOW_UNVERIFIED_SESSION / config field).
			runEnv := llmcontext.DefaultLookup
			if verErr := RequireVerifiedSession(runEnv, runtime.IsRawCredentialMode(mode), configAllowsUnverifiedSession(runEnv)); verErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "%v\n", verErr)
				os.Exit(exitcode.SecurityBlock)
			}

			// Guard 2: keyring must exist — if not, keylatch has never been bootstrapped.
			_, statErr := os.Stat(paths.KeyringPath(llmcontext.DefaultLookup))
			if statErr != nil {
				if os.IsNotExist(statErr) {
					cliErr := NewBootstrapMissing("keylatch not bootstrapped — run: keylatch bootstrap")
					fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
					os.Exit(exitcode.BootstrapMissing)
				}
				fmt.Fprintf(c.ErrOrStderr(), "warning: could not stat keyring: %v\n", statErr)
			}

			// Guard 3: connection for this provider must exist. Parse args first to
			// get the connection name (args before "--"). If parsing fails, fall
			// through — the downstream arg-validation will emit the proper error.
			if len(args) > 0 {
				connName, _, _ := parseRunArgs(args)
				if connName != "" {
					connCtx := c.Context()
					connBackend, connTmpl, connPath, connErr := loadConnectionBackend(connCtx, connName)
					if connErr == nil {
						// Backend loaded: check whether the credential actually exists.
						_, _, getErr := connBackend.Get(connCtx, connPath)
						_ = connBackend.Close()
						if errors.Is(getErr, backend.ErrNotFound) {
							cliErr := NewSecretNotFound("no connection for provider %q — run: keylatch setup %s", connName, connName)
							fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
							os.Exit(exitCodeSecretNotFound)
						}
						_ = connTmpl
					}
					// Any other error (e.g. ErrProviderNotFound, backend init failure) is
					// left for the primary run path to handle with richer context.
				}
			}

			// Validate mode early and suggest closest match on typo.
			if !isKnownMode(mode) {
				suggestion := suggestMode(string(mode))
				if suggestion != "" {
					fmt.Fprintf(c.ErrOrStderr(), "Error: unknown runtime mode %q. Did you mean %q?\n", mode, suggestion)
				} else {
					fmt.Fprintf(c.ErrOrStderr(), "Error: unknown runtime mode %q.\n", mode)
				}
				fmt.Fprintln(c.ErrOrStderr(), "  Run 'keylatch modes' to see all available modes.")
				os.Exit(exitcode.UserError)
			}

			// signingKey is nil here: the gateway signing key is not loaded at
			// CLI startup. GuardRuntime will block any approval JWT because it
			// cannot verify the signature — callers must obtain approval via a
			// running gateway instance that holds the key.
			if block, code := GuardRuntime(mode, approvalJWT, llmcontext.DefaultLookup, nil); block {
				WriteGuardRuntimeError(&stderrBuf, mode)
				fmt.Fprint(c.ErrOrStderr(), stderrBuf.String())
				os.Exit(code)
			}

			// No per-mode warning needed in v1.0.0 (direct_classic removed in T-10-03).

			// P1.2: gate --allow in LLM sessions.
			if len(rawAllows) > 0 && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "Error: flag --allow is not permitted in LLM sessions.")
				os.Exit(exitcode.SecurityBlock)
			}

			// Auto-spawn keylatchd if it is not already running (Epic 31).
			noDaemonStart, _ := c.Flags().GetBool("no-daemon-start")
			if !noDaemonStart && !daemon.IsRunning() {
				fmt.Fprintln(c.ErrOrStderr(), "Starting Keylatch daemon... (will run in background)")
				if err := daemon.Spawn(); err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "keylatch: %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
			}

			// Parse connection name and command: args before "--" is connection,
			// args after "--" is the command to execute.
			connectionName, command, parseErr := parseRunArgs(args)
			if parseErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", parseErr)
				os.Exit(exitcode.UserError)
			}
			if connectionName == "" {
				fmt.Fprintln(c.ErrOrStderr(), "keylatch run: missing <connection> argument")
				os.Exit(exitcode.UserError)
			}
			if len(command) == 0 {
				fmt.Fprintln(c.ErrOrStderr(), "keylatch run: missing <command> after --")
				os.Exit(exitcode.UserError)
			}

			ctx := c.Context()

			// T-09-01: --dry-run mode.
			// Show what would be injected and executed, then exit 0 (or non-zero
			// if the plan is not executable). Never decrypts a credential.
			dryRun, _ := c.Flags().GetBool("dry-run")
			jsonOut, _ := c.Flags().GetBool("json")
			if dryRun {
				runDryRun(c, connectionName, command, mode, modeFlag, approvalJWT, jsonOut)
				return nil
			}

			// Load config and backend.
			b, tmpl, storagePath, err := loadConnectionBackend(ctx, connectionName)
			if err != nil {
				if errors.Is(err, registry.ErrProviderNotFound) {
					fmt.Fprintf(c.ErrOrStderr(), "keylatch run: unknown connection %q\n", connectionName)
					os.Exit(exitcode.UserError)
				}
				fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			// P1.4: track start time for summary.
			start := time.Now()

			// Wire the DispatchRunner with the directClassicDriver and the
			// LLM session guard. GuardRuntime already ran above and either
			// exited or allowed the request — the guard here provides defence-in-depth
			// for the per-request path inside the runner pipeline.
			guardFn := runner.GuardFunc(func(m runtime.RuntimeMode, jwt string) bool {
				blocked, _ := GuardRuntime(m, jwt, llmcontext.DefaultLookup, nil)
				return blocked
			})

			// Load gateway signing key and token store for gateway/SDK drivers.
			// A missing key is not fatal at registration time — the gateway_typed
			// and gateway_sdk drivers will fail at Run() with a token-mint error
			// if the key is absent. This is acceptable: without a signing key the
			// gateway cannot have been initialized so gateway_is_running returns false.
			env := llmcontext.DefaultLookup
			signingKey, _ := os.ReadFile(paths.GatewaySigningKey(env))
			tokenStorePath := paths.GatewayTokens(env)
			pidPath := paths.GatewayPID(env)

			// gatewayAdapter implements GatewayTypedServerStarter / GatewaySDKServerStarter.
			gatewayAddr, addrErr := gatewayRunAddr(env)
			if addrErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", addrErr)
				os.Exit(exitcode.UserError)
			}
			gatewaySrv := &gatewayServerAdapter{
				addr:    gatewayAddr,
				pidPath: pidPath,
			}

			// Proxy server address for gateway_proxy mode.
			proxyAddr, proxyAddrErr := proxyRunAddr(env)
			if proxyAddrErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", proxyAddrErr)
				os.Exit(exitcode.UserError)
			}
			proxySrv := &proxy.Server{Addr: proxyAddr}
			// proxyLiveness reports whether the proxy daemon is running, based on ~/.keylatch/proxy.pid.
			proxyLiveness := func() bool {
				running, _, _ := proxyLiveness(env)
				return running
			}

			// EPIC-17: resolve operating mode from flag, env var, and config file.
			cfgPath := paths.Config(env)
			opCfg, cfgLoadErr := config.Load(cfgPath)
			if cfgLoadErr != nil {
				opCfg = config.Default()
			}
			opMode, _ := runtime.ResolveMode(modeFlag, runtime.OperatingMode(opCfg.Mode))
			opSettings := runtime.EffectiveSettingsForMode(opMode, mapCustomConfig(opCfg.Custom))

			dr := runner.DispatchRunner{
				Guard: guardFn,
				Drivers: map[string]runner.Driver{
					// v1.0.0 mode set.
					string(runtime.RuntimeGatewayTyped):   runner.NewGatewayTypedDriverWithSettings(gatewaySrv, signingKey, tokenStorePath, opSettings, nil),
					string(runtime.RuntimeGatewaySDK):     runner.NewGatewaySDKDriverWithSettings(gatewaySrv, signingKey, tokenStorePath, opSettings, nil),
					string(runtime.RuntimeDirectBrokered): runner.NewBrokeredDriver(b, newCLIBroker(ctx), nil),
					string(runtime.RuntimeGatewayProxy):   runner.WithLivenessGuard(runner.NewProxyDriver(proxySrv, signingKey, tokenStorePath, ""), proxyLiveness, runner.ErrProxyNotRunning),
					// EPIC-24: direct_classic_sandboxed reinstated.
					string(runtime.RuntimeDirectClassicSandboxed): runner.NewClassicSandboxedDriver(nil),
				},
			}

			// Build the extra allowlist for the --allow flag (CLI human-only override).
			// Accepts repeated flags and comma-joined values: --allow a,b --allow c
			var extraAllowed []string
			for _, r := range rawAllows {
				for _, part := range strings.Split(r, ",") {
					if p := strings.TrimSpace(part); p != "" {
						extraAllowed = append(extraAllowed, p)
					}
				}
			}

			// 2b: Levenshtein typo warning against known provider slugs.
			slugs := make([]string, 0, len(registry.List()))
			for _, t := range registry.List() {
				slugs = append(slugs, t.Provider)
			}
			for _, a := range extraAllowed {
				if sug := cmderr.SuggestProvider(a, slugs, 2); sug != "" {
					fmt.Fprintf(c.ErrOrStderr(), "Warning: %q is not a known provider slug. Did you mean %q?\n", a, sug)
				}
			}

			// T-08-02: read --clean-env and --extra flags.
			cleanEnv, _ := c.Flags().GetBool("clean-env")
			rawExtras, _ := c.Flags().GetStringArray("extra")
			var extraEnvVars []string
			for _, r := range rawExtras {
				for _, part := range strings.Split(r, ",") {
					if p := strings.TrimSpace(part); p != "" {
						extraEnvVars = append(extraEnvVars, p)
					}
				}
			}

			req := runner.ExecRequest{
				ConnectionSlug:       connectionName,
				Command:              command,
				WorkingDir:           "",
				Actor:                "",
				Capability:           "inject",
				TTL:                  0,
				Runtime:              string(mode),
				ApprovalJWT:          approvalJWT,
				Stdin:                c.InOrStdin(),
				Stdout:               c.OutOrStdout(),
				Stderr:               c.ErrOrStderr(),
				ExtraAllowedPrefixes: extraAllowed,
				CleanEnv:             cleanEnv,
				ExtraEnvVars:         extraEnvVars,
			}
			receipt, runErr := dr.Run(ctx, req)
			elapsed := time.Since(start)
			// Best-effort push to keylatchd dashboard (ignored if not running).
			pushReceiptToUI(ctx, receipt)

			_ = storagePath
			if runErr != nil {
				// Inspect structured RuntimeError first — emit canonical format and exit.
				var rte *runner.RuntimeError
				if errors.As(runErr, &rte) {
					fmt.Fprintf(c.ErrOrStderr(), "error[%s]: %s + %s: %s", rte.Class, rte.Provider, rte.Mode, rte.Reason)
					if rte.Fix != "" {
						fmt.Fprintf(c.ErrOrStderr(), ". %s", rte.Fix)
					}
					fmt.Fprintln(c.ErrOrStderr())
					_ = closeAndZeroBackend(b)
					exitCode := rte.ExitCode
					if exitCode == 0 {
						exitCode = exitcode.OperationFailed
					}
					os.Exit(exitCode)
				}
				if errors.Is(runErr, runner.ErrCommandNotAllowed) {
					// P1.2: actionable allowlist error.
					printAllowlistError(c, connectionName, command, tmpl.AllowedCommandPrefixes)
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.SecurityBlock)
				}
				if errors.Is(runErr, runner.ErrGuardDenied) {
					WriteGuardRuntimeError(c.ErrOrStderr(), mode)
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.SecurityBlock)
				}
				if errors.Is(runErr, runtime.ErrModeRemoved) {
					// T-10-03: removed mode returns exit 5 with hint.
					fmt.Fprintf(c.ErrOrStderr(), "error: %v\n", runErr)
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.RuntimeNotAvailable)
				}
				if errors.Is(runErr, backend.ErrNotFound) {
					fmt.Fprintf(c.ErrOrStderr(), "keylatch run: credential not found — run 'keylatch connect %s' first\n", connectionName)
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.Missing)
				}
				if errors.Is(runErr, runner.ErrGatewayNotRunning) {
					fmt.Fprintln(c.ErrOrStderr(), "keylatch: gateway is not running — starting it now (this happens once per session)...")

					// Attempt to auto-start the gateway in detached mode.
					selfPath, pathErr := os.Executable()
					if pathErr != nil {
						fmt.Fprintln(c.ErrOrStderr(), "Error: gateway is not running — run 'keylatch gateway up' first")
						_ = closeAndZeroBackend(b)
						os.Exit(exitcode.OperationFailed)
					}
					spawnCmd := exec.CommandContext(context.Background(), selfPath, "gateway", "up", "--detach")
					spawnCmd.Stderr = c.ErrOrStderr()
					if spawnErr := spawnCmd.Run(); spawnErr != nil {
						fmt.Fprintf(c.ErrOrStderr(), "Error: could not start gateway: %v\n", spawnErr)
						_ = closeAndZeroBackend(b)
						os.Exit(exitcode.OperationFailed)
					}

					// Poll until the gateway PID file appears (up to 10 seconds).
					deadline := time.Now().Add(10 * time.Second)
					for time.Now().Before(deadline) {
						if _, alive := gateway.IsRunning(pidPath); alive {
							break
						}
						time.Sleep(300 * time.Millisecond)
					}
					if _, alive := gateway.IsRunning(pidPath); !alive {
						fmt.Fprintln(c.ErrOrStderr(), "Error: gateway did not start in time — run 'keylatch gateway up' manually")
						_ = closeAndZeroBackend(b)
						os.Exit(exitcode.OperationFailed)
					}

					// Retry the run now that the gateway is up.
					fmt.Fprintln(c.ErrOrStderr(), "keylatch: gateway is up — retrying...")
					receipt, runErr = dr.Run(ctx, req)
					elapsed = time.Since(start)
					if runErr != nil {
						fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", runErr)
						_ = closeAndZeroBackend(b)
						os.Exit(exitcode.OperationFailed)
					}
				} else if errors.Is(runErr, runner.ErrProxyNotRunning) {
					fmt.Fprintln(c.ErrOrStderr(), runErr.Error())
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.OperationFailed)
				} else {
					fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", runErr)
					_ = closeAndZeroBackend(b)
					os.Exit(exitcode.OperationFailed)
				}
			}

			// P1.4: print success/failure summary to stderr.
			if receipt.ExitCode == 0 {
				fmt.Fprintf(c.ErrOrStderr(), "v %s — exit 0 (%s)\n", connectionName, elapsed.Round(time.Millisecond))
			} else {
				fmt.Fprintf(c.ErrOrStderr(), "x %s — exit %d (%s)\n", connectionName, receipt.ExitCode, elapsed.Round(time.Millisecond))
			}

			_ = closeAndZeroBackend(b)
			os.Exit(receipt.ExitCode)
			return nil
		},
	}
	cmd.Flags().String("runtime", string(runtime.RuntimeGatewayTyped),
		"runtime mode (default: gateway_typed — run 'keylatch modes' to see all options)")
	cmd.Flags().String("mode", "", "operating mode (standard, telemetry, canary, custom); overrides config file and KEYLATCH_MODE env var")
	cmd.Flags().String("approval-jwt", "", "approval JWT for direct_classic_sandboxed mode")
	cmd.Flags().StringArray("allow", nil, "allow this command prefix for this run only; repeat or comma-separate (blocked in LLM sessions)")
	cmd.Flags().Bool("no-daemon-start", false, "do not auto-start keylatchd if it is not running")
	cmd.Flags().Bool("dry-run", false, "show what would be injected and executed without running the command")
	cmd.Flags().Bool("json", false, "output dry-run plan as JSON (requires --dry-run)")
	cmd.Flags().Bool("clean-env", false, "exec the child with a minimal env (PATH, HOME, USER, SHELL, TERM, LANG + injected vars)")
	cmd.Flags().StringArray("extra", nil, "preserve these env vars when using --clean-env (comma-separated or repeated)")
	return cmd
}

// dryRunPolicy describes the policy fields included in a dry-run plan.
type dryRunPolicy struct {
	LLMSession       bool `json:"llm_session"`
	ApprovalRequired bool `json:"approval_required"`
}

// dryRunPlan is the machine-readable plan emitted by --dry-run --json.
// Schema version is always "v1".
type dryRunPlan struct {
	Schema      string       `json:"_schema"`
	Runtime     string       `json:"runtime"`
	Provider    string       `json:"provider"`
	Connection  string       `json:"connection"`
	EnvAdded    []string     `json:"env_added"`
	EnvStripped []string     `json:"env_stripped"`
	Argv        []string     `json:"argv"`
	Policy      dryRunPolicy `json:"policy"`
}

// dryRunError carries a machine-readable error class and detail for --dry-run --json output.
type dryRunError struct {
	Class  string `json:"class"`
	Detail string `json:"detail"`
}

// dryRunWrapper wraps the plan under a "plan" key for the JSON --json output.
// OK is false when the dry-run plan is not executable (e.g. connection not found).
// Error is set in the failure path so consumers do not have to rely on exit codes alone.
type dryRunWrapper struct {
	Schema string       `json:"_schema"`
	OK     bool         `json:"ok"`
	Error  *dryRunError `json:"error,omitempty"`
	Plan   dryRunPlan   `json:"plan"`
}

// runDryRun implements T-09-01: print what keylatch run would do without executing.
//
// Rules:
//   - Never decrypts a credential.
//   - For gateway modes, KEYLATCH_GATEWAY_TOKEN shown as placeholder string.
//   - Prints env_added (names only, no real values), env_stripped (KEYLATCH_* from parent env),
//     argv that would be exec'd, and policy flags.
//   - Exits 0 if the plan is executable, non-zero if not.
//   - Respects --json flag; JSON is: {"_schema":"v1","plan":{...}}.
//   - EPIC-17: when canary mode is active, KEYLATCH_CANARY_<PROVIDER> appears in env_added.
func runDryRun(c *cobra.Command, connectionName string, command []string, mode runtime.RuntimeMode, modeFlag string, approvalJWT string, jsonOut bool) {
	env := llmcontext.DefaultLookup
	isLLM := llmcontext.IsLLMSession(env)

	plan := dryRunPlan{
		Schema:      "v1",
		Runtime:     string(mode),
		Provider:    connectionName,
		Connection:  connectionName,
		EnvAdded:    []string{},
		EnvStripped: []string{},
		Argv:        command,
		Policy: dryRunPolicy{
			LLMSession:       isLLM,
			ApprovalRequired: approvalJWT != "",
		},
	}

	// Compute which KEYLATCH_* vars from the parent environment would be stripped.
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KEYLATCH_") {
			k := strings.SplitN(kv, "=", 2)[0]
			plan.EnvStripped = append(plan.EnvStripped, k)
		}
	}

	// Look up the provider template to get injection rules (metadata only).
	tmpl, registryErr := registry.Get(connectionName)
	if registryErr != nil {
		// No connection — SecretNotFound (exit 6).
		if jsonOut {
			detail := fmt.Sprintf("no connection for provider %q — run: keylatch connect %s", connectionName, connectionName)
			wrapper := dryRunWrapper{
				Schema: "v1",
				OK:     false,
				Error:  &dryRunError{Class: "SecretNotFound", Detail: detail},
				Plan:   plan,
			}
			b, marshalErr := json.MarshalIndent(wrapper, "", "  ")
			if marshalErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "keylatch: internal error marshalling dry-run plan: %v\n", marshalErr)
				os.Exit(exitCodeInternalError)
			}
			fmt.Fprintln(c.OutOrStdout(), string(b))
		} else {
			fmt.Fprintf(c.OutOrStdout(), "[dry-run] runtime:    %s\n", plan.Runtime)
			fmt.Fprintf(c.OutOrStdout(), "[dry-run] connection: %s — UNKNOWN (run: keylatch connect %s)\n", connectionName, connectionName)
			fmt.Fprintf(c.OutOrStdout(), "[dry-run] argv:       %s\n", strings.Join(command, " "))
		}
		cliErr := NewSecretNotFound("no connection for provider %q — run: keylatch connect %s", connectionName, connectionName)
		fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
		os.Exit(exitCodeSecretNotFound)
		return
	}

	// Build the env_added list (names only — no real values for sensitive vars).
	switch mode {
	case runtime.RuntimeGatewayTyped, runtime.RuntimeGatewaySDK:
		gatewayAddr, addrErr := gatewayRunAddr(env)
		if addrErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "keylatch run: %v\n", addrErr)
			os.Exit(exitcode.UserError)
		}
		plan.EnvAdded = append(plan.EnvAdded,
			"KEYLATCH_GATEWAY_URL=<resolved: http://"+gatewayAddr+">",
			"KEYLATCH_GATEWAY_TOKEN=<would-be-issued scope:"+tmpl.Provider+".*, ttl:1h>",
			"KEYLATCH_RUNTIME="+string(mode),
		)
	case runtime.RuntimeDirectBrokered:
		for _, rule := range tmpl.InjectionRules {
			plan.EnvAdded = append(plan.EnvAdded, rule.EnvVar+"=<would-be-brokered ephemeral token>")
		}
		plan.EnvAdded = append(plan.EnvAdded, "KEYLATCH_RUNTIME="+string(mode))
	case runtime.RuntimeGatewayProxy:
		plan.EnvAdded = append(plan.EnvAdded,
			"KEYLATCH_GATEWAY_TOKEN=<would-be-issued scope:"+tmpl.Provider+".*, ttl:1h>",
			"KEYLATCH_RUNTIME="+string(mode),
		)
	}

	// EPIC-17: if operating mode enables canary injection, include canary var in env_added.
	// Load config to resolve the operating mode (same precedence as the real run path).
	{
		dryRunCfgPath := paths.Config(env)
		dryRunCfg, dryRunCfgErr := config.Load(dryRunCfgPath)
		if dryRunCfgErr != nil {
			dryRunCfg = config.Default()
		}
		dryRunOpMode, _ := runtime.ResolveMode(modeFlag, runtime.OperatingMode(dryRunCfg.Mode))
		dryRunSettings := runtime.EffectiveSettingsForMode(dryRunOpMode, mapCustomConfig(dryRunCfg.Custom))
		if dryRunSettings.CanaryInjectionEnabled {
			plan.EnvAdded = append(plan.EnvAdded, canary.EnvVarName(tmpl.Provider)+"=<would-be-canary-token>")
		}
	}

	if jsonOut {
		wrapper := dryRunWrapper{Schema: "v1", OK: true, Plan: plan}
		b, marshalErr := json.MarshalIndent(wrapper, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "keylatch: internal error marshalling dry-run plan: %v\n", marshalErr)
			os.Exit(exitCodeInternalError)
		}
		fmt.Fprintln(c.OutOrStdout(), string(b))
		return
	}

	// Human-readable output.
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] runtime:    %s\n", plan.Runtime)
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] provider:   %s\n", plan.Provider)
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] connection: %s\n", plan.Connection)
	if len(plan.EnvAdded) > 0 {
		fmt.Fprintf(c.OutOrStdout(), "[dry-run] env_added:\n")
		for _, kv := range plan.EnvAdded {
			fmt.Fprintf(c.OutOrStdout(), "[dry-run]   %s\n", kv)
		}
	}
	if len(plan.EnvStripped) > 0 {
		fmt.Fprintf(c.OutOrStdout(), "[dry-run] env_stripped: %s\n", strings.Join(plan.EnvStripped, ", "))
	}
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] argv:       %s\n", strings.Join(command, " "))
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] policy:     llm_session=%v approval_required=%v\n",
		plan.Policy.LLMSession, plan.Policy.ApprovalRequired)
	fmt.Fprintf(c.OutOrStdout(), "[dry-run] no command executed\n")
	_ = approvalJWT // already captured in plan.Policy.ApprovalRequired
}

// printAllowlistError prints the P1.2 actionable allowlist error message.
func printAllowlistError(c *cobra.Command, connectionName string, command []string, allowed []string) {
	cmdName := ""
	if len(command) > 0 {
		cmdName = command[0]
	}
	fmt.Fprintf(c.ErrOrStderr(), "Error: %q is not in the allowlist for the %s connection.\n", cmdName, connectionName)
	if len(allowed) > 0 {
		fmt.Fprintf(c.ErrOrStderr(), "\n  Allowed: %s\n", strings.Join(allowed, ", "))
	}
	fmt.Fprintf(c.ErrOrStderr(), "\n  To allow %s for this run only:\n", cmdName)
	fmt.Fprintf(c.ErrOrStderr(), "    keylatch run %s --allow %s -- %s\n", connectionName, cmdName, strings.Join(command, " "))
	fmt.Fprintln(c.ErrOrStderr())
	fmt.Fprintln(c.ErrOrStderr(), "  Why an allowlist? It prevents an attacker (or LLM session) from substituting")
	fmt.Fprintln(c.ErrOrStderr(), "  a different binary that could exfiltrate the credential.")
}

// parseRunArgs splits positional args into (connectionName, command).
// Expected form: <connection> -- <command...>
// If no "--" separator is present, the first arg is the connection name and
// the rest is treated as the command.
// Returns an error if more than one argument appears before "--", because
// extra junk arguments are likely a user mistake that should surface as an error
// rather than being silently ignored.
func parseRunArgs(args []string) (string, []string, error) {
	// Find "--" separator.
	for i, a := range args {
		if a == "--" {
			if i == 0 {
				return "", args[i+1:], nil
			}
			if i > 1 {
				return "", nil, fmt.Errorf("unexpected arguments before '--': %v", args[1:i])
			}
			return args[0], args[i+1:], nil
		}
	}
	// No "--": first arg = connection, rest = command.
	if len(args) == 0 {
		return "", nil, nil
	}
	return args[0], args[1:], nil
}

// closeAndZeroBackend closes b and, if it holds decrypted key material in
// memory (currently: only the file backend's attached keyring), zeroes it
// (L2: docker-server-security hardening).
//
// Only call this at a command's TERMINAL exit point (immediately before
// os.Exit / process end) — internal/backend/dispatch.Select caches backend
// instances per-process (sync.Once), so the same instance can legitimately
// be Close()'d by an intermediate existence check and then reused for the
// real operation later in the same process. Zeroing at a non-terminal
// Close() would corrupt the DEK for that later reuse. See
// file.FileBackend.Close's doc comment for the full rationale.
func closeAndZeroBackend(b backend.Backend) error {
	err := b.Close()
	if z, ok := b.(interface{ ZeroKeyring() }); ok {
		z.ZeroKeyring()
	}
	return err
}

// loadConnectionBackend loads the config and backend for the given connection name.
// For MVP: connection name == provider slug, namespace = "default", account = "default".
func loadConnectionBackend(ctx context.Context, connectionName string) (backend.Backend, registry.ConnectionTemplate, string, error) {
	env := llmcontext.DefaultLookup

	// Load config (ignore file-not-found — use defaults).
	cfgPath := paths.Config(env)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		cfg = config.Default()
	}

	// Look up the provider template.
	tmpl, err := registry.Get(connectionName)
	if err != nil {
		if errors.Is(err, registry.ErrProviderNotFound) {
			return nil, registry.ConnectionTemplate{}, "", registry.ErrProviderNotFound
		}
		return nil, registry.ConnectionTemplate{}, "", fmt.Errorf("registry lookup %q: %w", connectionName, err)
	}

	// Build the connection meta path — the path keylatch connect stores metadata at.
	// Using StoragePathTpl would render the account-namespaced prefix (e.g.
	// "default/ai/anthropic/default") which never matches any stored entry;
	// the meta path ("default/ai/anthropic/meta") is what connect actually writes.
	category := tmpl.Category
	if category == "" {
		category = "ai"
	}
	storagePath := fmt.Sprintf("default/%s/%s/meta", category, connectionName)

	// Select backend.
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, registry.ConnectionTemplate{}, "", fmt.Errorf("backend: %w", err)
	}

	return b, tmpl, storagePath, nil
}

// newCallCmd returns the `call` subcommand with runtime guards.
// S0-5: NOT value-bearing.
//
//nolint:unused // planned: wired to root command when call/describe/validate are promoted from Phase 9
func newCallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "call <connection> <endpoint>",
		Short: "Call an endpoint via a credential connection",
		RunE: func(c *cobra.Command, args []string) error {
			mode := runtime.RuntimeMode(c.Flag("runtime").Value.String())
			approvalJWT := c.Flag("approval-jwt").Value.String()
			if block, code := GuardRuntime(mode, approvalJWT, llmcontext.DefaultLookup, nil); block {
				WriteGuardRuntimeError(c.ErrOrStderr(), mode)
				os.Exit(code)
			}
			os.Exit(exitcode.OperationFailed)
			return nil
		},
	}
	cmd.Flags().String("runtime", string(runtime.RuntimeGatewayTyped), "runtime mode")
	cmd.Flags().String("approval-jwt", "", "approval JWT for direct_classic_sandboxed mode")
	return cmd
}

// newDescribeCmd returns the `describe` subcommand — NOT guarded.
// S0-5: describe is a safe path.
//
//nolint:unused // planned: wired to root command when call/describe/validate are promoted from Phase 9
func newDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <service>",
		Short: "Describe a credential (no values)",
		RunE:  notImplementedRunE(exitcode.OperationFailed),
	}
}

// newValidateCmd returns the `validate` subcommand — NOT guarded.
// S0-5: validate is a safe path.
//
//nolint:unused // planned: wired to root command when call/describe/validate are promoted from Phase 9
func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <service>",
		Short: "Validate a credential without returning its value",
		RunE:  notImplementedRunE(exitcode.OperationFailed),
	}
}

// newListCmd is replaced by newListCmdImpl in list_cmd.go (Phase 1).
// Kept as a reference for Phase 0 behavior: the original stub exited with
// exitcode.OperationFailed.

// newConnectionsCmd returns the `connections` subcommand — NOT guarded.
// S0-5: connections is a safe path.
// Delegates to the same list implementation used by `keylatch list` so that
// `keylatch connections` and `keylatch connections list` both work.
func newConnectionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connections",
		Short: "List credential connections",
		// Default: delegate to the list implementation so `keylatch connections`
		// produces the same output as `keylatch list` (exit 0).
		RunE: func(c *cobra.Command, args []string) error {
			return newListCmdImpl().RunE(c, args)
		},
	}
	// Add `list` as a subcommand so `keylatch connections list` also works.
	listSub := newListCmdImpl()
	listSub.Use = "list"
	listSub.Short = "List credential connections"
	cmd.AddCommand(listSub)
	return cmd
}

//nolint:unused // used by newDescribeCmd and newValidateCmd (Phase 9 stubs)
func notImplementedRunE(code int) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		os.Exit(code)
		return nil // unreachable
	}
}

func handlerArgsFromCmd(c *cobra.Command, positional []string) HandlerArgs {
	return HandlerArgs{
		Positional: positional,
		Flags:      map[string]string{},
		Env:        llmcontext.DefaultLookup,
		Stdin:      c.InOrStdin(),
		Stdout:     c.OutOrStdout(),
		Stderr:     c.ErrOrStderr(),
	}
}

// gatewayServerAdapter implements runner.GatewayTypedServerStarter and
// runner.GatewaySDKServerStarter for the production CLI path. It reads the
// gateway address from the config and checks liveness via the PID file.
type gatewayServerAdapter struct {
	addr    string
	pidPath string
}

func (a *gatewayServerAdapter) Addr() string { return a.addr }
func (a *gatewayServerAdapter) Running() bool {
	_, running := gateway.IsRunning(a.pidPath)
	return running
}

// gatewayRunAddr resolves the gateway listen address.
// Priority: KEYLATCH_GATEWAY_ADDR env var → 127.0.0.1:7878 default.
// Returns a clear error if KEYLATCH_GATEWAY_ADDR is set but not valid host:port.
func gatewayRunAddr(env llmcontext.Lookup) (string, error) {
	if v := env("KEYLATCH_GATEWAY_ADDR"); v != "" {
		if err := validateHostPort(v); err != nil {
			return "", fmt.Errorf("KEYLATCH_GATEWAY_ADDR: %w", err)
		}
		return v, nil
	}
	return "127.0.0.1:7878", nil
}

// proxyRunAddr resolves the proxy listen address.
// Priority: KEYLATCH_PROXY_ADDR env var → 127.0.0.1:7879 default.
// Returns a clear error if KEYLATCH_PROXY_ADDR is set but not valid host:port.
func proxyRunAddr(env llmcontext.Lookup) (string, error) {
	if v := env("KEYLATCH_PROXY_ADDR"); v != "" {
		if err := validateHostPort(v); err != nil {
			return "", fmt.Errorf("KEYLATCH_PROXY_ADDR: %w", err)
		}
		return v, nil
	}
	return "127.0.0.1:7879", nil
}

// mapCustomConfig converts a config.CustomModeConfig pointer to a
// runtime.CustomModeConfig pointer for use with EffectiveSettingsForMode.
// Returns nil if cfg is nil.
func mapCustomConfig(cfg *config.CustomModeConfig) *runtime.CustomModeConfig {
	if cfg == nil {
		return nil
	}
	return &runtime.CustomModeConfig{
		TelemetryEnabled:       cfg.TelemetryEnabled,
		CanaryInjectionEnabled: cfg.CanaryInjectionEnabled,
		ExperimentalGated:      cfg.ExperimentalGated,
	}
}

// newCLIBroker returns a BrokerExchanger suitable for the CLI direct_brokered
// path. It has no registered provider strategies, so it returns
// broker.ErrUnsupportedExchange for any provider that does not have a registered
// strategy. This is acceptable behaviour for the initial wiring: the error
// surfaces as a driver error and is reported to the user with an actionable
// message via the standard error path.
func newCLIBroker(ctx context.Context) runner.BrokerExchanger {
	// The hmacKey (3rd nil) is intentionally nil here. When nil, broker.hashID
	// returns the constant "no-hmac-key" placeholder — actor/session IDs are not
	// HMAC'd in the CLI direct-brokered path because no signing key is loaded at
	// broker construction time (the signing key lives in the gateway process, not
	// the CLI). The audit MAC key is derived inside audit.Open from the audit salt
	// via DeriveChainMACKey — passing nil here is correct; it is not used externally.
	return broker.NewBroker(ctx, nil, nil, nil)
}
