package cli

import (
	"bufio"
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend/keychain"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	klruntime "github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/spf13/cobra"
)

const (
	launchdLabel     = "io.keylatch.keylatchd"
	launchdPlistName = launchdLabel + ".plist"
)

// stdinScannerFn constructs a new bufio.Scanner over os.Stdin.
// Declared as a var so tests can replace it with a scanner over a pipe or
// bytes.Buffer without touching os.Stdin at package-init time.
//
// C2: lazy init replaces the package-level stdinScanner to preserve test isolation.
var stdinScannerFn = func() *bufio.Scanner {
	return bufio.NewScanner(os.Stdin)
}

var (
	scannerOnce   sync.Once
	sharedScanner *bufio.Scanner
)

// storeNewResolver returns a store.Resolver backed by the real exec runner.
// Declared as a var so tests can stub it without binary substitution.
//
// W5: converted from a plain function to an injectable var.
var storeNewResolver = func() *store.Resolver {
	return store.NewResolver(kexec.DefaultRunner)
}

// validURISegment matches safe path segments in provider-ref URIs.
// Only alphanumeric characters, underscores, hyphens, and dots are permitted.
// Forward-slashes are NOT allowed here — each segment is validated individually.
//
// W6: used to sanitize op:// (and other scheme) path segments before exec.
var validURISegment = regexp.MustCompile(`^[A-Za-z0-9_\-\.]+$`)

// setupHeadlessResult is written to stderr as JSON when --headless is used.
type setupHeadlessResult struct {
	OK      bool   `json:"ok"`
	Backend string `json:"backend,omitempty"`
	Error   string `json:"error,omitempty"`
}

// platformBackend returns the recommended backend name and a human-readable
// description for the current OS.
func platformBackend() (name, desc string) {
	switch runtime.GOOS {
	case "darwin":
		return "keychain", "macOS Keychain"
	case "linux":
		// Prefer secret-service when GNOME is present.
		if os.Getenv("GNOME_DESKTOP_SESSION_ID") != "" || os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return "secret-service", "GNOME Secret Service"
		}
		return "file", "encrypted file (~/.keylatch/)"
	case "windows":
		return "wincred", "Windows Credential Manager"
	default:
		return "file", "encrypted file (~/.keylatch/)"
	}
}

// newSetupCmd returns the `keylatch setup` wizard command.
// Epic 26: restructured into 5 named steps with [N/5] progress output.
// §2.4: --from-env, --stdin-field, --non-interactive, --headless flags preserved.
func newSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Interactive first-run wizard: configure backend, connect a provider, start daemon",
		Long: `setup walks you through the entire keylatch configuration in five steps:

  [1/5] Detect platform       — detect OS, recommend the best secret backend
  [2/5] Backend setup         — confirm and configure the credential backend
  [3/5] Spawn daemon          — ensure keylatchd is running
  [4/5] Connect provider      — connect your first API key provider
  [5/5] Open app (optional)   — launch Keylatch.app (macOS)

Non-interactive / headless usage:

  keylatch setup --headless --backend=keychain
  keylatch setup --headless --backend=keychain --config=./keylatch.yaml

Advanced mode (all backend options):

  keylatch setup --advanced

Exit codes:
  0  success
  1  user error (missing required field, invalid input)
  2  security block (LLM session detected)
  5  operation failed (backend error)`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()

			headless, _ := c.Flags().GetBool("headless")
			nonInteractive, _ := c.Flags().GetBool("non-interactive")
			fromEnv, _ := c.Flags().GetBool("from-env")
			stdinFields, _ := c.Flags().GetStringArray("stdin-field")
			advanced, _ := c.Flags().GetBool("advanced")
			noDaemonStart, _ := c.Flags().GetBool("no-daemon-start")
			_ = advanced      // consumed below in interactive mode
			_ = noDaemonStart // consumed in step 3

			// In headless mode, suppress all stdout output; only JSON to stderr.
			// In non-interactive mode, do not prompt — fail if required data is missing.
			isNonInteractive := headless || nonInteractive || fromEnv || len(stdinFields) > 0

			// LLM session guard: interactive setup must not run inside an AI session.
			// Headless/non-interactive modes are explicitly allowed.
			if !isNonInteractive && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "Error: setup must be run interactively — not inside an AI session.")
				os.Exit(exitcode.SecurityBlock)
				return nil
			}

			// Headless mode: parse --backend, run bootstrap, emit JSON to stderr, exit.
			if headless {
				return runSetupHeadless(c, ctx)
			}

			force, _ := c.Flags().GetBool("force")

			// Detect existing config.
			cfgPath := paths.Config(llmcontext.DefaultLookup)
			if !force {
				if cfg, err := config.Load(cfgPath); err == nil && cfg.Backend != "" {
					if isNonInteractive {
						// Non-interactive: idempotent OK — already configured.
						fmt.Fprintln(c.ErrOrStderr(), `{"ok":true,"note":"already configured"}`)
						return nil
					}
					fmt.Fprintln(c.OutOrStdout(), "You're already set up. Run `keylatch doctor` to verify.")
					return nil
				}
			}

			// Non-interactive: require --backend flag; skip prompts.
			var backend string
			var err error
			if isNonInteractive {
				backend, _ = c.Flags().GetString("backend")
				if backend == "" {
					// Try from-env.
					if fromEnv {
						backend = os.Getenv("KEYLATCH_BACKEND")
					}
				}
				// Parse stdin-fields for any future use.
				if _, fieldErr := ResolveStdinFields(stdinFields); fieldErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", fieldErr)
					os.Exit(exitcode.UserError)
					return nil
				}
				if backend == "" {
					fmt.Fprintln(c.ErrOrStderr(), "Error: --non-interactive requires --backend (file|keychain|op|bw) or KEYLATCH_BACKEND env var.")
					os.Exit(exitcode.UserError)
					return nil
				}
			} else {
				// Print welcome banner.
				fmt.Fprintln(c.OutOrStdout(), "Welcome to Keylatch.")
				fmt.Fprintln(c.OutOrStdout(), "Keylatch keeps your API keys out of AI tools and lets you audit what was used.")
				fmt.Fprintln(c.OutOrStdout())

				// Top-level branch: local AEAD storage or external provider reference?
				branch, branchErr := setupPromptStorageBranch(c)
				if branchErr != nil {
					return branchErr
				}

				if branch == "reference" {
					return setupRunReferenceBranch(c, ctx)
				}

				// local branch: existing 5-step wizard.

				// Step 1: Detect platform.
				backend, err = setupStep1DetectPlatform(c, advanced)
				if err != nil {
					return err
				}

				// Step 2: Backend setup — confirm + bootstrap.
				_, err = setupStep2BackendSetup(c, ctx, backend)
				if err != nil {
					return err
				}

				// Step 2b: Operating mode choice (EPIC-17).
				setupStepModeChoice(c, advanced)

				// Step 3: Spawn daemon.
				if !noDaemonStart {
					setupStep3SpawnDaemon(c)
				}

				// Step 4: Connect provider.
				setupStep4ConnectProvider(c)

				// Step 5: Open app (optional).
				setupStep5OpenApp(c)

				return nil
			}

			// Run bootstrap with the chosen backend (non-interactive path).
			_, err = bootstrap.Run(ctx, bootstrap.Options{
				DryRun:  false,
				Backend: backend,
				Env:     llmcontext.DefaultLookup,
			})
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "bootstrap: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			return nil
		},
	}
	cmd.Flags().Bool("force", false, "re-run setup even if already configured")
	cmd.Flags().String("backend", "", "credential backend: file, keychain (macOS only), op, bw")
	cmd.Flags().Bool("headless", false, "headless mode: no prompts, JSON result on stderr, deterministic exit codes")
	cmd.Flags().Bool("non-interactive", false, "fail instead of prompting when required fields are missing")
	cmd.Flags().Bool("from-env", false, "read field values from KEYLATCH_<FIELD_NAME> environment variables")
	cmd.Flags().StringArray("stdin-field", nil, "supply a field value as key=value (may be repeated)")
	cmd.Flags().Bool("advanced", false, "show all backend options and advanced configuration (audit dir, signing key, ports, telemetry)")
	cmd.Flags().Bool("no-daemon-start", false, "skip daemon start in step 3 (useful in CI or restricted environments)")
	cmd.Flags().String("config", "", "path to keylatch.yaml config file")
	cmd.Flags().String("telemetry", "", "telemetry setting: on|off")
	return cmd
}

// runSetupHeadless runs setup in headless mode: accepts --backend, no prompts,
// writes JSON result to stderr, returns deterministic exit codes.
// §2.4 headless submode.
func runSetupHeadless(c *cobra.Command, ctx context.Context) error {
	backend, _ := c.Flags().GetString("backend")
	if backend == "" {
		backend = "file"
	}

	writeHeadlessResult := func(ok bool, backend string, errMsg string) {
		res := setupHeadlessResult{OK: ok, Backend: backend, Error: errMsg}
		b, _ := json.Marshal(res)
		fmt.Fprintln(c.ErrOrStderr(), string(b))
	}

	_, err := bootstrap.Run(ctx, bootstrap.Options{
		DryRun:  false,
		Backend: backend,
		Env:     llmcontext.DefaultLookup,
	})
	if err != nil {
		writeHeadlessResult(false, backend, err.Error())
		os.Exit(exitcode.OperationFailed)
		return nil
	}

	// Initialize the audit keyring for the file backend (best-effort, non-blocking).
	if backend == "file" {
		initAuditKeyring()
	}

	writeHeadlessResult(true, backend, "")
	return nil
}

// initAuditKeyring creates the audit keyring at $VAULT/keyring/keyring.json
// using the age-env identity from bootstrap. Idempotent and best-effort.
func initAuditKeyring() {
	vaultDir := paths.Vault(llmcontext.DefaultLookup)
	auditKrDir := filepath.Join(vaultDir, "keyring")
	auditKrPath := filepath.Join(auditKrDir, "keyring.json")
	if _, err := os.Stat(auditKrPath); err == nil {
		return // already exists
	}
	if err := os.MkdirAll(auditKrDir, 0o700); err != nil {
		return
	}
	identityPath := paths.KeyringIdentityPath(llmcontext.DefaultLookup)
	auditSalt := make([]byte, 32)
	if _, err := cryptoRand.Read(auditSalt); err != nil {
		return
	}
	auditKEK, err := kek.AgeIdentityKEKFromPath(identityPath, auditSalt)
	if err != nil {
		return
	}
	_ = keyring.NewWithSalt(auditKrPath, auditKEK, envelope.XChaCha20Poly1305, 0, auditSalt)
}

// ResolveStdinFields parses --stdin-field key=value flags into a map.
// Fields must be in "key=value" form; malformed entries are returned as errors.
// Exported for testing.
func ResolveStdinFields(stdinFields []string) (map[string]string, error) {
	out := make(map[string]string, len(stdinFields))
	for _, kv := range stdinFields {
		idx := strings.IndexByte(kv, '=')
		if idx < 1 {
			return nil, fmt.Errorf("--stdin-field %q: must be in key=value form", kv)
		}
		out[kv[:idx]] = kv[idx+1:]
	}
	return out, nil
}

// setupStep1DetectPlatform handles [1/5] — detect OS and recommend the best backend.
// Returns the recommended backend slug.
func setupStep1DetectPlatform(c *cobra.Command, advanced bool) (string, error) {
	fmt.Fprintln(c.OutOrStdout(), "[1/5] Detecting platform...")
	fmt.Fprintln(c.OutOrStdout())

	recommended, recDesc := platformBackend()
	goos := runtime.GOOS
	fmt.Fprintf(c.OutOrStdout(), "  Platform: %s\n", goos)
	fmt.Fprintf(c.OutOrStdout(), "  Recommended backend: %s (%s)\n", recommended, recDesc)
	fmt.Fprintln(c.OutOrStdout())

	return recommended, nil
}

// setupStep2BackendSetup handles [2/5] — confirm backend and run bootstrap.
// Takes the recommended backend from step 1; returns the chosen backend.
func setupStep2BackendSetup(c *cobra.Command, ctx context.Context, recommended string) (string, error) {
	fmt.Fprintln(c.OutOrStdout(), "[2/5] Backend setup...")
	fmt.Fprintln(c.OutOrStdout())

	advanced, _ := c.Flags().GetBool("advanced")
	flagBackend, _ := c.Flags().GetString("backend")

	chosen := recommended
	telemetrySetting := ""

	if flagBackend != "" {
		// --backend flag overrides the recommendation.
		chosen = flagBackend
		fmt.Fprintf(c.OutOrStdout(), "  Using --backend=%s\n", chosen)
		// Honour --telemetry off flag even in non-advanced mode.
		if tf, _ := c.Flags().GetString("telemetry"); strings.ToLower(tf) == "off" {
			telemetrySetting = "off"
		}
	} else if advanced {
		// Advanced mode: show all 10 backend options and telemetry prompt.
		chosen, telemetrySetting = setupPromptAdvancedBackend(c, recommended)
	} else {
		// Standard: prompt "Use recommended backend? (Y/n)".
		fmt.Fprintf(c.OutOrStdout(), "  Use recommended backend [%s]? (Y/n): ", recommended)
		ans := readLine()
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans == "n" || ans == "no" {
			chosen = setupPromptBasicBackend(c, recommended)
		}
	}

	fmt.Fprintf(c.OutOrStdout(), "  Configuring backend %q...\n", chosen)

	_, err := bootstrap.Run(ctx, bootstrap.Options{
		DryRun:  false,
		Backend: chosen,
		Env:     llmcontext.DefaultLookup,
	})
	if err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "  bootstrap: %v\n", err)
		return "", fmt.Errorf("bootstrap failed: %w", err)
	}

	// On macOS with keychain backend, initialize the keychain so the unlock
	// password is stored in the login keychain. Without this, every subsequent
	// `keylatch connect` fails with "keychain: read unlock password: security exited 44".
	if chosen == "keychain" && runtime.GOOS == "darwin" {
		fmt.Fprintf(c.OutOrStdout(), "  Initialising keychain backend...\n")

		// Open directly with defaults — avoids dispatch caching issues since
		// Open() fills KeychainPath/LockPath/SecurityBin/Runner/Env from defaults.
		kb, kbErr := keychain.Open(keychain.Options{})
		if kbErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "  Error: keychain open: %v\n", kbErr)
			return "", fmt.Errorf("keychain open: %w", kbErr)
		}
		if initErr := kb.Init(ctx, "default"); initErr != nil {
			fmt.Fprintf(c.ErrOrStderr(), "  Error: keychain-init: %v\n", initErr)
			return "", fmt.Errorf("keychain init: %w", initErr)
		}
	}

	// For the file backend, also initialize the audit keyring (best-effort).
	if chosen == "file" {
		initAuditKeyring()
	}

	// Persist telemetry setting to config when the user explicitly opted in or out.
	if telemetrySetting != "" {
		cfgPath := paths.Config(llmcontext.DefaultLookup)
		cfg, loadErr := config.Load(cfgPath)
		if loadErr == nil {
			cfg.Telemetry.Enabled = strings.ToLower(telemetrySetting) == "on"
			if cfg.Telemetry.Enabled {
				cfg.Telemetry.Sink = "local"
			}
			_ = config.Save(cfgPath, cfg) // best-effort — setup is still successful
		}
	}

	fmt.Fprintf(c.OutOrStdout(), "  Backend %q configured.\n\n", chosen)
	return chosen, nil
}

// setupPromptBasicBackend shows the standard 4-option backend menu.
func setupPromptBasicBackend(c *cobra.Command, recommended string) string {
	isMacOS := runtime.GOOS == "darwin"

	fmt.Fprintln(c.OutOrStdout(), "  Choose a backend:")
	fmt.Fprintln(c.OutOrStdout(), "    1) Encrypted file in ~/.keylatch/   (works everywhere)")
	fmt.Fprintln(c.OutOrStdout(), "    2) macOS Keychain                    (macOS only)")
	fmt.Fprintln(c.OutOrStdout(), "    3) 1Password (1password-cli required, "+detectCLI("op")+")")
	fmt.Fprintln(c.OutOrStdout(), "    4) Bitwarden (bitwarden-cli required, "+detectCLI("bw")+")")
	fmt.Fprintln(c.OutOrStdout())

	defaultChoice := "1"
	if isMacOS {
		defaultChoice = "2"
	}
	fmt.Fprintf(c.OutOrStdout(), "  Choose [%s]: ", defaultChoice)

	choice := readLine()
	if choice == "" {
		choice = defaultChoice
	}

	switch choice {
	case "1":
		return "file"
	case "2":
		if !isMacOS {
			fmt.Fprintln(c.ErrOrStderr(), "  macOS Keychain is only available on macOS. Using file backend.")
			return "file"
		}
		return "keychain"
	case "3":
		return "op"
	case "4":
		return "bw"
	default:
		fmt.Fprintf(c.OutOrStdout(), "  Invalid choice — using %q.\n", recommended)
		return recommended
	}
}

// setupPromptAdvancedBackend shows all available backend options (--advanced mode).
// Returns the chosen backend slug and the resolved telemetry setting ("on", "off", or "").
func setupPromptAdvancedBackend(c *cobra.Command, recommended string) (string, string) {
	fmt.Fprintln(c.OutOrStdout(), "  Advanced backend options:")
	fmt.Fprintln(c.OutOrStdout(), "    1)  file            — encrypted file in ~/.keylatch/")
	fmt.Fprintln(c.OutOrStdout(), "    2)  keychain        — macOS Keychain (macOS only)")
	fmt.Fprintln(c.OutOrStdout(), "    3)  op              — 1Password CLI")
	fmt.Fprintln(c.OutOrStdout(), "    4)  bw              — Bitwarden CLI")
	fmt.Fprintln(c.OutOrStdout(), "    5)  secret-service  — GNOME Secret Service (Linux)")
	fmt.Fprintln(c.OutOrStdout(), "    6)  wincred         — Windows Credential Manager")
	fmt.Fprintln(c.OutOrStdout(), "    7)  vault           — HashiCorp Vault")
	fmt.Fprintln(c.OutOrStdout(), "    8)  doppler         — Doppler secrets manager")
	fmt.Fprintln(c.OutOrStdout(), "    9)  aws-secrets     — AWS Secrets Manager")
	fmt.Fprintln(c.OutOrStdout(), "    10) azure-keyvault  — Azure Key Vault")
	fmt.Fprintln(c.OutOrStdout())

	// Advanced port, audit, and key configuration will be added in a future phase
	// when bootstrap.Options gains the corresponding fields.

	// Telemetry opt-in: --telemetry off skips prompt; otherwise ask (default NO).
	telemetryFlag, _ := c.Flags().GetString("telemetry")
	chosenTelemetry := telemetryFlag
	if strings.ToLower(telemetryFlag) == "off" {
		chosenTelemetry = "off"
	} else if telemetryFlag == "" {
		fmt.Fprintln(c.OutOrStdout())
		fmt.Fprintf(c.OutOrStdout(), "    Allow anonymous usage stats? This sends 7 anonymised metrics\n")
		fmt.Fprintf(c.OutOrStdout(), "    (no keys, no values) to help improve Keylatch. (y/N): ")
		ans := strings.ToLower(strings.TrimSpace(readLine()))
		if ans == "y" || ans == "yes" {
			chosenTelemetry = "on"
		} else {
			chosenTelemetry = "off"
		}
	}
	if chosenTelemetry != "" {
		fmt.Fprintf(c.OutOrStdout(), "  Telemetry: %s\n", chosenTelemetry)
	}
	fmt.Fprintln(c.OutOrStdout())

	advancedMap := map[string]string{
		"1": "file", "2": "keychain", "3": "op", "4": "bw",
		"5": "secret-service", "6": "wincred", "7": "vault",
		"8": "doppler", "9": "aws-secrets", "10": "azure-keyvault",
	}
	fmt.Fprintf(c.OutOrStdout(), "  Choose backend [recommended: %s, enter number]: ", recommended)
	choice := strings.TrimSpace(readLine())
	chosen, ok := advancedMap[choice]
	if !ok {
		fmt.Fprintf(c.OutOrStdout(), "  Using recommended backend %q.\n", recommended)
		return recommended, chosenTelemetry
	}

	// Validate that the chosen backend is supported by bootstrap.Run.
	// Backends in the menu that are planned for a future release are not yet wired.
	supported := map[string]bool{"file": true, "keychain": true, "op": true, "bw": true, "secret-service": true}
	if !supported[chosen] {
		fmt.Fprintf(c.ErrOrStderr(), "  Error: backend %q is planned for a future release and not yet available — use one of: file, keychain, op, bw, secret-service\n", chosen)
		fmt.Fprintf(c.OutOrStdout(), "  Using recommended backend %q.\n", recommended)
		return recommended, chosenTelemetry
	}

	return chosen, chosenTelemetry
}

// setupStepModeChoice prompts the user to select an operating mode (EPIC-17).
//
// Basic (non-advanced) prompt shows standard and telemetry.
// If the user picks "advanced", all four modes are shown.
// The selected mode is persisted via `keylatch config set mode <choice>`.
func setupStepModeChoice(c *cobra.Command, advanced bool) {
	fmt.Fprintln(c.OutOrStdout(), "Operating mode:")
	fmt.Fprintln(c.OutOrStdout(), "  standard   — no telemetry, no canary injection (default)")
	fmt.Fprintln(c.OutOrStdout(), "  telemetry  — enable anonymous usage telemetry")

	if advanced {
		fmt.Fprintln(c.OutOrStdout(), "  canary     — inject canary tokens for leak detection")
		fmt.Fprintln(c.OutOrStdout(), "  custom     — configure individual flags (edit config.json)")
	} else {
		fmt.Fprintln(c.OutOrStdout(), "  (type 'advanced' to see all modes)")
	}
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintf(c.OutOrStdout(), "  Choose mode [standard]: ")

	answer := strings.ToLower(strings.TrimSpace(readLine()))
	if answer == "" || answer == "standard" {
		// Standard is default; no need to write it explicitly.
		fmt.Fprintln(c.OutOrStdout(), "  Operating mode: standard")
		fmt.Fprintln(c.OutOrStdout())
		return
	}

	// If the user typed "advanced" in basic mode, re-prompt with all four modes.
	if answer == "advanced" && !advanced {
		fmt.Fprintln(c.OutOrStdout(), "  All modes:")
		fmt.Fprintln(c.OutOrStdout(), "    standard   — no telemetry, no canary injection")
		fmt.Fprintln(c.OutOrStdout(), "    telemetry  — enable anonymous usage telemetry")
		fmt.Fprintln(c.OutOrStdout(), "    canary     — inject canary tokens for leak detection")
		fmt.Fprintln(c.OutOrStdout(), "    custom     — configure individual flags (edit config.json)")
		fmt.Fprintln(c.OutOrStdout())
		fmt.Fprintf(c.OutOrStdout(), "  Choose mode [standard]: ")
		answer = strings.ToLower(strings.TrimSpace(readLine()))
		if answer == "" {
			answer = "standard"
		}
	}

	if _, err := klruntime.ParseMode(answer); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "  Unknown mode %q — using standard.\n", answer)
		fmt.Fprintln(c.OutOrStdout())
		return
	}

	// Persist the mode via config.
	cfgPath := paths.Config(llmcontext.DefaultLookup)
	cfg, loadErr := config.Load(cfgPath)
	if loadErr != nil {
		cfg = config.Default()
	}
	cfg.Mode = answer
	if saveErr := config.Save(cfgPath, cfg); saveErr != nil {
		fmt.Fprintf(c.ErrOrStderr(), "  Warning: could not persist operating mode: %v\n", saveErr)
	} else {
		fmt.Fprintf(c.OutOrStdout(), "  Operating mode: %s\n", answer)
	}
	fmt.Fprintln(c.OutOrStdout())
}

// setupStep3SpawnDaemon handles [3/5] — ensure keylatchd is running.
func setupStep3SpawnDaemon(c *cobra.Command) {
	fmt.Fprintln(c.OutOrStdout(), "[3/5] Daemon setup...")
	fmt.Fprintln(c.OutOrStdout())

	switch runtime.GOOS {
	case "darwin":
		setupSpawnDaemonDarwin(c)
	case "linux":
		setupSpawnDaemonLinux(c)
	default:
		fmt.Fprintln(c.OutOrStdout(), "  Daemon auto-start is not supported on this platform.")
		fmt.Fprintln(c.OutOrStdout(), "  Start keylatchd manually to use gateway features.")
	}

	fmt.Fprintln(c.OutOrStdout())
}

// setupSpawnDaemonDarwin handles daemon launch on macOS via launchd.
func setupSpawnDaemonDarwin(c *cobra.Command) {
	plistPath := os.ExpandEnv("$HOME/Library/LaunchAgents/" + launchdPlistName)
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		fmt.Fprintln(c.OutOrStdout(), "  Daemon state: not installed (launchd plist missing)")
		fmt.Fprintln(c.OutOrStdout(), "  To install: keylatch gateway install")
		return
	}

	// Try to load/start via launchctl.
	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	if err := cmd.Run(); err != nil {
		// May already be loaded — try start.
		startCmd := exec.Command("launchctl", "start", launchdLabel)
		if startErr := startCmd.Run(); startErr != nil {
			fmt.Fprintf(c.OutOrStdout(), "  Daemon state: could not start (%v)\n", startErr)
			fmt.Fprintf(c.OutOrStdout(), "  To start manually: launchctl start %s\n", launchdLabel)
			fmt.Fprintln(c.OutOrStdout(), "  Note: gateway features (AI agent credential injection) will not work until keylatchd is running.")
			return
		}
	}
	fmt.Fprintln(c.OutOrStdout(), "  Daemon state: running (via launchd)")
}

// setupSpawnDaemonLinux handles daemon launch on Linux via systemd user service.
func setupSpawnDaemonLinux(c *cobra.Command) {
	// Check if systemd is available.
	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(c.OutOrStdout(), "  Daemon state: systemd not detected")
		fmt.Fprintln(c.OutOrStdout(), "  Start manually: keylatchd &")
		return
	}

	// Print the systemd enable command — do not run automatically.
	fmt.Fprintln(c.OutOrStdout(), "  To enable keylatchd via systemd:")
	fmt.Fprintln(c.OutOrStdout(), "    systemctl --user enable --now keylatchd")
	fmt.Fprintln(c.OutOrStdout(), "  Or start directly: keylatchd &")
	fmt.Fprintln(c.OutOrStdout(), "  Note: gateway features (AI agent credential injection) will not work until keylatchd is running.")
}

// setupStep4ConnectProvider handles [4/5] — interactive provider picker.
// Shows a numbered list from the registry; user picks by number or name.
func setupStep4ConnectProvider(c *cobra.Command) {
	fmt.Fprintln(c.OutOrStdout(), "[4/5] Connect your first provider...")
	fmt.Fprintln(c.OutOrStdout())

	// Verify backend was initialized before attempting to connect.
	cfgPath := paths.Config(llmcontext.DefaultLookup)
	if _, err := config.Load(cfgPath); err != nil {
		fmt.Fprintln(c.ErrOrStderr(), "  Warning: backend config not found — skipping provider connection.")
		fmt.Fprintln(c.ErrOrStderr(), "  Run `keylatch setup` to initialise the backend first.")
		fmt.Fprintln(c.OutOrStdout())
		return
	}

	templates := registry.List()

	// Fall back to a minimal default list when the registry is empty.
	type providerEntry struct{ slug, display, category string }
	var entries []providerEntry
	if len(templates) > 0 {
		for _, t := range templates {
			entries = append(entries, providerEntry{t.Provider, t.DisplayName, t.Category})
		}
	} else {
		entries = []providerEntry{
			{"anthropic", "Anthropic", "ai"},
			{"openai", "OpenAI", "ai"},
			{"openrouter", "OpenRouter", "ai"},
			{"sentry", "Sentry", "observability"},
		}
	}

	// Print numbered list.
	for i, e := range entries {
		fmt.Fprintf(c.OutOrStdout(), "  %3d)  %-22s  %s\n", i+1, e.display, e.category)
	}
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintf(c.OutOrStdout(), "  Choose [1-%d, name, or Enter to skip]: ", len(entries))

	ans := strings.TrimSpace(readLine())
	if ans == "" || strings.ToLower(ans) == "n" || strings.ToLower(ans) == "no" {
		fmt.Fprintln(c.OutOrStdout(), "  Skipping — run `keylatch connect <provider>` when ready.")
		fmt.Fprintln(c.OutOrStdout())
		return
	}

	provider := ans
	if n, err := strconv.Atoi(ans); err == nil && n >= 1 && n <= len(entries) {
		provider = entries[n-1].slug
	}

	fmt.Fprintf(c.OutOrStdout(), "  Running: keylatch connect %s\n\n", provider)
	self, err := os.Executable()
	if err != nil {
		self = "keylatch"
	}
	connectCmd := exec.Command(self, "connect", provider) //nolint:gosec // provider is user-supplied input, not a shell command
	connectCmd.Stdin = os.Stdin
	connectCmd.Stdout = c.OutOrStdout()
	connectCmd.Stderr = c.ErrOrStderr()
	if err := connectCmd.Run(); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "  keylatch connect: %v\n", err)
	}

	fmt.Fprintln(c.OutOrStdout())
}

// setupStep5OpenApp handles [5/5] — offer to open the desktop app (optional, default N).
func setupStep5OpenApp(c *cobra.Command) {
	fmt.Fprintln(c.OutOrStdout(), "[5/5] Open Keylatch app (optional)...")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintf(c.OutOrStdout(), "  Open Keylatch.app? (y/N): ")

	ans := readLine()
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "y" && ans != "yes" {
		fmt.Fprintln(c.OutOrStdout(), "  Skipping.")
		fmt.Fprintln(c.OutOrStdout())
		printSetupSuccess(c)
		return
	}

	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("open", "/Applications/Keylatch.app")
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "  Could not open Keylatch.app: %v\n", err)
			fmt.Fprintln(c.OutOrStdout(), "  Open manually from /Applications/Keylatch.app")
		} else {
			fmt.Fprintln(c.OutOrStdout(), "  Keylatch.app opened.")
		}
	case "linux":
		// Try xdg-open for Linux desktop launchers.
		if path, err := exec.LookPath("xdg-open"); err == nil {
			cmd := exec.Command(path, "keylatch://open")
			if err := cmd.Start(); err != nil {
				fmt.Fprintln(c.OutOrStdout(), "  Could not open app via xdg-open.")
			} else {
				fmt.Fprintln(c.OutOrStdout(), "  App launch requested.")
			}
		} else {
			fmt.Fprintln(c.OutOrStdout(), "  Desktop app not available on this Linux setup.")
		}
	case "windows":
		cmd := exec.Command("cmd", "/c", "start", "keylatch:")
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "  Could not open app: %v\n", err)
		} else {
			fmt.Fprintln(c.OutOrStdout(), "  App launch requested.")
		}
	default:
		fmt.Fprintln(c.OutOrStdout(), "  App launch not supported on this platform.")
	}

	fmt.Fprintln(c.OutOrStdout())
	printSetupSuccess(c)
}

// printSetupSuccess prints the final success banner.
func printSetupSuccess(c *cobra.Command) {
	fmt.Fprintln(c.OutOrStdout(), "You're set up!")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "Next steps:")
	fmt.Fprintln(c.OutOrStdout(), "  keylatch connect <provider>                  connect a provider")
	fmt.Fprintln(c.OutOrStdout(), "  keylatch run <provider> -- <command>         run a command with credentials injected")
	fmt.Fprintln(c.OutOrStdout(), "  keylatch doctor                              health check anytime")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "Docs: https://docs.keylatch.io")
}

// setupPromptStorageBranch asks whether the user wants local AEAD storage or an
// external provider-reference URI. Returns "local", "reference", or an error if
// the user chose to quit.
//
// EPIC-11 (Task 1): top-level branch inserted before the 5-step wizard.
func setupPromptStorageBranch(c *cobra.Command) (string, error) {
	fmt.Fprintln(c.OutOrStdout(), "How would you like to store credentials?")
	fmt.Fprintln(c.OutOrStdout(), "  local     — encrypt and store the secret locally (AEAD)")
	fmt.Fprintln(c.OutOrStdout(), "  reference — reference a secret from a password manager (op://, aws-sm://, hashivault://)")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintf(c.OutOrStdout(), "  Store credentials locally (AEAD) or reference from a password manager? [local/reference/q]: ")

	for {
		answer := strings.ToLower(strings.TrimSpace(readLine()))
		switch answer {
		case "", "local", "l":
			fmt.Fprintln(c.OutOrStdout())
			return "local", nil
		case "reference", "ref", "r":
			fmt.Fprintln(c.OutOrStdout())
			return "reference", nil
		case "q", "quit", "exit":
			fmt.Fprintln(c.OutOrStdout(), "Setup cancelled.")
			os.Exit(exitcode.OK)
			return "", nil
		default:
			fmt.Fprintf(c.OutOrStdout(), "  Please enter 'local', 'reference', or 'q' to quit: ")
		}
	}
}

// setupRunReferenceBranch handles the "reference" branch of the setup wizard.
//
// Steps:
//  1. Prompt for the provider-ref URI (e.g. op://vault/item/field).
//  2. Validate the URI format via store.ValidateProviderRefURI.
//  3. Attempt a dry-run resolution to verify the external CLI is reachable.
//  4. On success: print a confirmation message and next-step hint.
//
// EPIC-11 (Task 1): reference branch — defers resolution to runtime.
func setupRunReferenceBranch(c *cobra.Command, ctx context.Context) error {
	fmt.Fprintln(c.OutOrStdout(), "Reference mode: Keylatch will store a URI and resolve it at runtime.")
	fmt.Fprintln(c.OutOrStdout(), "Supported URI schemes: op://, aws-sm://, hashivault://")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "Example URIs:")
	fmt.Fprintln(c.OutOrStdout(), "  op://Private/Anthropic/api_key")
	fmt.Fprintln(c.OutOrStdout(), "  aws-sm://us-east-1/my-secret")
	fmt.Fprintln(c.OutOrStdout(), "  hashivault://secret/myapp/config#api_key")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintf(c.OutOrStdout(), "  Provider reference URI: ")

	uri := strings.TrimSpace(readLine())
	if uri == "" {
		fmt.Fprintln(c.ErrOrStderr(), "Error: URI is required for reference mode.")
		os.Exit(exitcode.UserError)
		return nil
	}

	// Step 2: validate URI format.
	if err := store.ValidateProviderRefURI(uri); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "Error: invalid provider-ref URI: %v\n", err)
		fmt.Fprintln(c.ErrOrStderr(), "  Run 'keylatch setup' again with a valid URI.")
		os.Exit(exitcode.UserError)
		return nil
	}

	// W6: validate each path segment of the URI to prevent injection via shell exec.
	// Strip the scheme prefix (e.g. "op://") and split the remainder on "/".
	// Fragments (#) are treated as a separate segment.
	if segErr := validateURISegments(uri); segErr != nil {
		cliErr := NewUsageError("provider-ref URI contains an invalid segment: %v", segErr)
		fmt.Fprint(c.ErrOrStderr(), cliErr.Stderr())
		os.Exit(exitcode.UserError)
		return nil
	}

	fmt.Fprintf(c.OutOrStdout(), "  URI format: valid\n")

	// Step 3: dry-run resolution — verify the external CLI is reachable.
	fmt.Fprintf(c.OutOrStdout(), "  Verifying external store is reachable (dry-run)...")
	r := storeNewResolver()
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resolveWarning := false
	if _, resolveErr := r.Resolve(resolveCtx, uri); resolveErr != nil {
		// Resolution failed — warn but do not block setup. The URI may be valid
		// but the external CLI might not be authenticated yet.
		fmt.Fprintln(c.OutOrStdout(), " warning")
		fmt.Fprintf(c.ErrOrStderr(), "  Warning: dry-run resolution failed: %v\n", resolveErr)
		resolveWarning = true
	} else {
		fmt.Fprintln(c.OutOrStdout(), " ok")
	}

	// Step 4: persist the URI to config so it can be referenced later.
	cfgPath := paths.Config(llmcontext.DefaultLookup)
	cfg, loadErr := config.Load(cfgPath)
	if loadErr != nil {
		cfg = config.Default()
	}
	cfg.DefaultProviderRef = uri
	if saveErr := config.Save(cfgPath, cfg); saveErr != nil {
		fmt.Fprintf(c.ErrOrStderr(), "  Error: could not persist provider-ref URI: %v\n", saveErr)
		os.Exit(exitcode.OperationFailed)
		return nil
	}

	if resolveWarning {
		fmt.Fprintln(c.ErrOrStderr(), "  Ensure the external CLI is authenticated before using 'keylatch run'.")
	}

	// Step 5: report what was stored and print next-step hint.
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "URI saved.")
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "What was stored:")
	fmt.Fprintf(c.OutOrStdout(), "  provider-ref URI: %s\n", uri)
	fmt.Fprintln(c.OutOrStdout())
	fmt.Fprintln(c.OutOrStdout(), "Next: run `keylatch connect <provider> --provider-ref api_key=<uri>` to finish enrollment.")
	fmt.Fprintf(c.OutOrStdout(), "  Example: keylatch connect <provider> --provider-ref api_key=%s\n", uri)

	return nil
}

// validateURISegments checks that every path segment in a provider-ref URI
// matches validURISegment. This prevents injection when the URI is later used
// in a shell exec (e.g. `op read op://vault/item/field`).
//
// W6: called by setupRunReferenceBranch before persistence or exec.
func validateURISegments(uri string) error {
	// Strip scheme (everything up to and including "://").
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return fmt.Errorf("no scheme separator in URI")
	}
	rest := uri[idx+3:]

	// Separate fragment (#field) if present.
	fragment := ""
	if fi := strings.LastIndex(rest, "#"); fi >= 0 {
		fragment = rest[fi+1:]
		rest = rest[:fi]
	}

	segments := strings.Split(rest, "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if !validURISegment.MatchString(seg) {
			return fmt.Errorf("segment %q contains characters outside [A-Za-z0-9_\\-.]", seg)
		}
		if seg == ".." || seg == "." {
			return fmt.Errorf("segment %q: dot-segments not permitted in provider reference URI", seg)
		}
	}
	if fragment != "" && !validURISegment.MatchString(fragment) {
		return fmt.Errorf("fragment %q contains characters outside [A-Za-z0-9_\\-.]", fragment)
	}
	return nil
}

// detectCLI returns "detected" or "not detected" for a CLI binary.
func detectCLI(name string) string {
	_, err := findExecutable(name)
	if err != nil {
		return "not detected"
	}
	return "detected"
}

// findExecutable looks up a binary in PATH, correctly checking executable permission bits.
func findExecutable(name string) (string, error) {
	return exec.LookPath(name)
}

// readLine reads a single line from stdin using the shared scanner.
// The scanner is initialised lazily on first call via sync.Once so that tests
// can replace stdinScannerFn before any readLine() call — allowing stdin
// redirection without capturing os.Stdin at package-init time.
func readLine() string {
	scannerOnce.Do(func() { sharedScanner = stdinScannerFn() })
	if sharedScanner.Scan() {
		return strings.TrimRight(sharedScanner.Text(), "\r\n")
	}
	return ""
}
