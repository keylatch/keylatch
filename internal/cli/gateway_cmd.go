// Package cli contains gateway subcommands.
package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/budget"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/gateway/docker"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/version"
	"github.com/spf13/cobra"
)

// newGatewayCmd returns the `keylatch gateway` group command.
func newGatewayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Manage the local typed provider gateway",
	}
	cmd.AddCommand(newGatewayInitCmd())
	cmd.AddCommand(newGatewayUpCmd())
	cmd.AddCommand(newGatewayDownCmd())
	cmd.AddCommand(newGatewayStatusCmd())
	cmd.AddCommand(newGatewayTokenCmd())
	cmd.AddCommand(newGatewayLogsCmd())
	cmd.AddCommand(newGatewayInstallCmd())
	return cmd
}

// desktopAppRunningFunc and launchctlRunFunc are declared as vars (mirroring
// stdinScannerFn in setup_cmd.go) so tests can substitute fakes without ever
// touching the real process table or invoking the real launchctl binary.
var (
	desktopAppRunningFunc = desktopAppRunning
	launchctlRunFunc      = func(args ...string) ([]byte, error) {
		return exec.Command("launchctl", args...).CombinedOutput() //nolint:gosec // args are fixed, non-user-controlled
	}
)

// newGatewayInstallCmd returns the `keylatch gateway install` command.
// On macOS it writes the keylatchd launchd plist and loads it via launchctl.
// On other platforms it prints an unsupported message.
func newGatewayInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install keylatchd as a launchd service (macOS only)",
		RunE: func(c *cobra.Command, _ []string) error {
			if runtime.GOOS != "darwin" {
				fmt.Fprintln(c.OutOrStdout(), "  gateway install is not supported on this platform")
				return nil
			}

			if desktopAppRunningFunc() {
				fmt.Fprintln(c.OutOrStdout(), "  Keylatch.app is already managing keylatchd — skipping launchd install to avoid a port 7890 conflict.")
				return nil
			}

			plistPath := launchdPlistPath()
			if err := installLaunchdPlist(plistPath); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "  gateway install: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			// Idempotency check: `launchctl load -w` on an already-loaded
			// label can hard-error on some macOS versions ("service already
			// loaded") even though nothing is actually wrong. `launchctl
			// list <label>` exits 0 iff the label is currently loaded — skip
			// the load call entirely in that case rather than risking a
			// spurious failure on a harmless re-run.
			if _, err := launchctlRunFunc("list", launchdServiceLabel()); err == nil {
				fmt.Fprintf(c.OutOrStdout(), "  keylatchd already installed and loaded (label: %s) — skipping\n", launchdServiceLabel())
				return nil
			}

			if out, err := launchctlRunFunc("load", "-w", plistPath); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "  gateway install: launchctl load: %v\n", err)
				if len(out) > 0 {
					fmt.Fprintf(c.ErrOrStderr(), "  %s\n", strings.TrimSpace(string(out)))
				}
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "  keylatchd installed and loaded from %s\n", filepath.Base(plistPath))
			return nil
		},
	}
}

// --- gateway init ---

func newGatewayInitCmd() *cobra.Command {
	var useDocker bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise the gateway (generate signing key, config)",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup

			// Create gateway directory.
			gatewayDir := paths.GatewayDir(env)
			if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
				return fmt.Errorf("gateway init: mkdir %q: %w", gatewayDir, err)
			}

			// Generate signing key if absent.
			keyPath := paths.GatewaySigningKey(env)
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				key := make([]byte, 32)
				if _, err := rand.Read(key); err != nil {
					return fmt.Errorf("gateway init: generate signing key: %w", err)
				}
				if err := os.WriteFile(keyPath, key, 0o600); err != nil {
					return fmt.Errorf("gateway init: write signing key: %w", err)
				}
				_ = os.Chmod(keyPath, 0o600)
				fmt.Fprintln(c.OutOrStdout(), "gateway: signing key generated")
			} else {
				fmt.Fprintln(c.OutOrStdout(), "gateway: signing key already exists")
			}

			// Write gateway config. M1: a re-run must not clobber a
			// previously customised bind/mode — only missing fields are
			// filled with defaults, existing values are kept as-is.
			cfgPath := paths.GatewayConfig(env)
			defaults := map[string]interface{}{
				"version": version.Version,
				"bind":    "127.0.0.1:7878",
				"mode":    "local_process",
			}

			cfg := map[string]interface{}{}
			existed := false
			if data, readErr := os.ReadFile(cfgPath); readErr == nil {
				existed = true
				if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "gateway: warning: existing config at %s is not valid JSON (%v) — rewriting with defaults\n", cfgPath, jsonErr)
					cfg = map[string]interface{}{}
					existed = false
				}
			}

			var kept, filled []string
			for k, v := range defaults {
				if k == "version" {
					// version always tracks the current build; it is not a
					// user-customisable field.
					cfg[k] = v
					continue
				}
				if _, ok := cfg[k]; ok {
					kept = append(kept, k)
					continue
				}
				cfg[k] = v
				filled = append(filled, k)
			}

			cfgData, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(cfgPath, cfgData, 0o600); err != nil {
				return fmt.Errorf("gateway init: write config: %w", err)
			}
			_ = os.Chmod(cfgPath, 0o600)

			if existed && len(kept) > 0 {
				sort.Strings(kept)
				fmt.Fprintf(c.OutOrStdout(), "gateway: kept existing values: %s\n", strings.Join(kept, ", "))
			}
			if len(filled) > 0 {
				sort.Strings(filled)
				fmt.Fprintf(c.OutOrStdout(), "gateway: filled missing fields with defaults: %s\n", strings.Join(filled, ", "))
			}
			fmt.Fprintf(c.OutOrStdout(), "gateway: config written to %s\n", cfgPath)

			// Optionally write Docker Compose.
			if useDocker {
				composePath := paths.GatewayDir(env) + "/docker-compose.yml"
				if err := docker.WriteAt(composePath, docker.ComposeOptions{
					Port:    7878,
					Version: version.Version,
				}); err != nil {
					return fmt.Errorf("gateway init: write compose: %w", err)
				}
				fmt.Fprintf(c.OutOrStdout(), "gateway: docker-compose.yml written to %s\n", composePath)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&useDocker, "docker", false, "also generate Docker Compose file")
	return cmd
}

// --- gateway up ---

func newGatewayUpCmd() *cobra.Command {
	var (
		port          int
		detach        bool
		unsafeBindAll bool
		listenAddr    string
		withProxy     bool
		proxyPort     int
		budgetPerHour float64
		budgetPerDay  float64
		force         bool
	)
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Start the local process gateway",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup

			// Check if gateway is already running. L2: with --force, a
			// "running" pid is not taken at face value — it may be a stale
			// pid file pointing at a recycled, unrelated process.
			pidPath := paths.GatewayPID(env)
			action, runningPID, note := resolveGatewayUpRunning(c.Context(), pidPath, force, kexec.DefaultRunner, kexec.Resolve("ps"))
			switch action {
			case gatewayUpRefuse:
				fmt.Fprintf(c.ErrOrStderr(), "Error: Gateway is already running (pid: %d).\n", runningPID)
				if note != "" {
					fmt.Fprintf(c.ErrOrStderr(), "  %s\n", note)
				}
				fmt.Fprintln(c.ErrOrStderr())
				fmt.Fprintln(c.ErrOrStderr(), "  Use `keylatch gateway down` to stop it.")
				os.Exit(exitcode.UserError)
				return nil
			case gatewayUpProceed:
				if note != "" {
					fmt.Fprintf(c.OutOrStdout(), "gateway: %s\n", note)
				}
			}

			if detach {
				// Refuse --detach when running via `go run`.
				// `go run` compiles to a temp binary; re-exec'ing it would
				// either fail (binary deleted) or start a dangling process
				// tied to the go run session. Detect this condition early.
				if isGoRunArtifact() {
					fmt.Fprintln(c.ErrOrStderr(), "Error: --detach is not supported when running via `go run`.")
					fmt.Fprintln(c.ErrOrStderr(), "  Build first: go build -o keylatch ./cmd/keylatch && ./keylatch gateway up --detach")
					os.Exit(exitcode.UserError)
				}

				// Detach: relaunch this binary without --detach so the child
				// runs as an independent background process. Platform-specific
				// isolation (new session / new process group) is handled by
				// startDetached, defined in gateway_cmd_unix.go / gateway_cmd_windows.go.
				childArgs := []string{"gateway", "up", fmt.Sprintf("--port=%d", port)}
				if unsafeBindAll {
					childArgs = append(childArgs, "--unsafe-bind-all")
				}
				if listenAddr != "" {
					// docker-server-security: validate --listen up front so a
					// malformed value fails immediately in the parent, rather
					// than surfacing later as a raw net.Listen error inside the
					// detached child.
					if err := validateHostPort(listenAddr); err != nil {
						fmt.Fprintf(c.ErrOrStderr(), "gateway: %v\n", err)
						os.Exit(exitcode.UserError)
					}
					childArgs = append(childArgs, "--listen="+listenAddr)
				}
				if budgetPerHour > 0 {
					childArgs = append(childArgs, fmt.Sprintf("--budget-per-hour=%g", budgetPerHour))
				}
				if budgetPerDay > 0 {
					childArgs = append(childArgs, fmt.Sprintf("--budget-per-day=%g", budgetPerDay))
				}
				if err := startDetached(childArgs, pidPath); err != nil {
					return err
				}
				// Poll for PID file written by child (up to 3 s).
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if data, err := os.ReadFile(pidPath); err == nil {
						fmt.Fprintf(c.OutOrStdout(), "gateway: started in background (pid: %s)\n", strings.TrimSpace(string(data)))
						return nil
					}
					time.Sleep(50 * time.Millisecond)
				}
				fmt.Fprintln(c.OutOrStdout(), "gateway: started in background")
				return nil
			}

			// Load signing key.
			keyPath := paths.GatewaySigningKey(env)
			signingKey, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("gateway up: read signing key %q: %w", keyPath, err)
			}
			if len(signingKey) != 32 {
				return fmt.Errorf("gateway up: signing key must be 32 bytes (run 'gateway init' first)")
			}

			// LLM sessions never get a non-loopback bind, regardless of flags/env
			// (fail closed). gateway.New() enforces this independently; suppressing
			// the inputs here keeps the CLI's own messaging/printed address accurate.
			isLLM := llmcontext.IsLLMSession(env)
			effectiveListenAddr := listenAddr
			bindEnv := env
			if isLLM {
				if unsafeBindAll {
					fmt.Fprintln(c.ErrOrStderr(), "gateway: LLM session detected — --unsafe-bind-all ignored")
					unsafeBindAll = false
				}
				if effectiveListenAddr != "" || env(gateway.EnvListenKey) != "" {
					fmt.Fprintln(c.ErrOrStderr(), "gateway: LLM session detected — --listen/KEYLATCH_GATEWAY_LISTEN ignored")
					effectiveListenAddr = ""
					bindEnv = func(string) string { return "" }
				}
			}
			bind, allowExternalBind, bindErr := resolveAndValidateGatewayBindAddr(port, effectiveListenAddr, unsafeBindAll, bindEnv)
			if bindErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "gateway: %v\n", bindErr)
				os.Exit(exitcode.UserError)
			}
			unsafeBindAll = unsafeBindAll || allowExternalBind

			// Open audit logger on a best-effort basis. If the keyring is not set
			// up (no passphrase / DEK), the gateway still starts without audit.
			var auditLogger *audit.Logger
			if al, cleanup, auditErr := openAuditLogger(); auditErr == nil {
				defer cleanup()
				auditLogger = al
			} else {
				fmt.Fprintf(c.ErrOrStderr(), "warning: audit logger unavailable (%v) — vault operations will not be audited\n", auditErr)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer cancel()

			// Per-actor budget enforcement: requests count 1 against the
			// hourly/daily windows when configured (0 = disabled).
			var budgetCounter budget.BudgetCounter
			if budgetPerHour > 0 || budgetPerDay > 0 {
				budgetCounter = budget.NewInMemoryBudgetCounter(ctx, budget.BudgetPolicy{
					SpendPerHour: budgetPerHour,
					SpendPerDay:  budgetPerDay,
				})
			}

			opts := gateway.ServerOptions{
				Bind:              bind,
				SigningKey:        signingKey,
				Mode:              gateway.ModeLocalProcess,
				Env:               env,
				ApprovalsDir:      paths.ApprovalsDir(env),
				TokenStorePath:    paths.GatewayTokens(env),
				AllowExternalBind: unsafeBindAll,
				AuditLogger:       auditLogger,
				Budget:            budgetCounter,
				// PolicyPath: default policy location (H7). New() treats a
				// missing file as "not configured" and stays pass-through —
				// this does not change behavior for operators who have
				// never created a policy file.
				PolicyPath: paths.Policy(env),
			}

			srv, err := gateway.New(opts)
			if err != nil {
				return fmt.Errorf("gateway up: %w", err)
			}

			// Write PID file atomically (write-to-tmp then rename) so the
			// parent's poll loop sees a complete file or nothing at all.
			if err := gateway.WritePID(pidPath, os.Getpid()); err != nil {
				return fmt.Errorf("gateway up: write PID: %w", err)
			}
			defer func() { _ = os.Remove(pidPath) }() //nolint:errcheck // PID cleanup on exit; error non-actionable in defer

			fmt.Fprintf(c.OutOrStdout(), "gateway: listening on %s\n", bind)

			// --with-proxy: start the proxy alongside the gateway.
			// W5: check both PID liveness AND stored port to determine whether the
			// running proxy is already on the requested port.
			if withProxy {
				proxyPidPath := proxyPIDPath(env)
				proxyStatePth := proxyStatePathFromDir(paths.ConfigDir(env))
				proxyAlreadyRunning := false
				if _, pidRunning := gateway.IsRunning(proxyPidPath); pidRunning {
					// Check if the running proxy is on the same port.
					if st, stErr := readProxyState(proxyStatePth); stErr == nil && st.Port == proxyPort {
						proxyAlreadyRunning = true
					}
					// If port differs, fall through and start on the requested port.
				}
				if proxyAlreadyRunning {
					fmt.Fprintf(c.OutOrStdout(), "gateway: proxy already running on the same port — skipping proxy start\n")
				} else {
					if _, proxyErr := startProxyWithGateway(ctx, proxyPort, proxyPidPath); proxyErr != nil {
						// Proxy failed to start — roll back gateway.
						fmt.Fprintf(c.ErrOrStderr(), "gateway up: proxy start failed (%v) — rolling back gateway\n", proxyErr)
						cancel()
						return fmt.Errorf("gateway up --with-proxy: %w", proxyErr)
					}
					fmt.Fprintf(c.OutOrStdout(), "gateway: proxy started on 127.0.0.1:%d\n", proxyPort)
				}
			}

			return srv.Serve(ctx)
		},
	}
	cmd.Flags().IntVar(&port, "port", 7878, "port to listen on")
	cmd.Flags().BoolVar(&detach, "detach", false, "run gateway as a background process")
	cmd.Flags().BoolVar(&unsafeBindAll, "unsafe-bind-all", false, "allow non-loopback bind (non-LLM sessions only)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "explicit non-loopback bind address, e.g. 0.0.0.0:7878 (Docker; non-LLM sessions only; overrides KEYLATCH_GATEWAY_LISTEN)")
	cmd.Flags().BoolVar(&withProxy, "with-proxy", false, "also start the CONNECT proxy alongside the gateway")
	cmd.Flags().IntVar(&proxyPort, "proxy-port", 8888, "port for the CONNECT proxy listener (requires --with-proxy)")
	cmd.Flags().Float64Var(&budgetPerHour, "budget-per-hour", 0, "per-actor request budget per hour (in-memory; resets on gateway restart; 0 = disabled)")
	cmd.Flags().Float64Var(&budgetPerDay, "budget-per-day", 0, "per-actor request budget per day (in-memory; resets on gateway restart; 0 = disabled)")
	cmd.Flags().BoolVar(&force, "force", false, "when the gateway appears to be running, verify process identity and recover from a stale PID file if it doesn't match a keylatch process")
	return cmd
}

// gatewayUpAction is the decision resolveGatewayUpRunning returns to RunE.
type gatewayUpAction int

const (
	// gatewayUpProceed: no gateway is running (or a stale PID was
	// successfully recovered) — safe to continue starting a new one.
	gatewayUpProceed gatewayUpAction = iota
	// gatewayUpRefuse: a gateway is running (and, if --force was used,
	// process identity verification confirmed it, or verification is
	// unsupported/inconclusive without --force) — RunE must exit non-zero.
	gatewayUpRefuse
)

// resolveGatewayUpRunning checks whether the gateway is already running and,
// if force is true, attempts best-effort stale-PID recovery via process
// identity verification (L2): IsRunning only signal-0-probes the pid, so a
// recycled pid can false-positive as "gateway running".
//
// Side effect: when recovery succeeds (pid confirmed stale, or identity is
// inconclusive and force was explicitly requested), the PID file is removed
// so gateway up can proceed to start a fresh instance.
//
// Kept as a standalone, side-effect-isolated function (rather than inlined
// in RunE) so it is unit-testable with a mocked runner and without starting
// a real server.
func resolveGatewayUpRunning(ctx context.Context, pidPath string, force bool, runner kexec.CommandRunner, psBin string) (action gatewayUpAction, pid int, note string) {
	pid, running := gateway.IsRunning(pidPath)
	if !running {
		return gatewayUpProceed, 0, ""
	}
	if !force {
		return gatewayUpRefuse, pid, ""
	}
	if runtime.GOOS == "windows" {
		return gatewayUpRefuse, pid, "--force stale-PID recovery via process-identity verification is not supported on this platform; stop the running gateway with `keylatch gateway down` or `keylatch daemon stop --force` (removes the PID file without signaling)."
	}

	matched, checked := gateway.VerifyProcessIdentity(ctx, runner, psBin, pid)
	switch {
	case checked && matched:
		return gatewayUpRefuse, pid, "process identity verification confirmed pid belongs to a running keylatch gateway — refusing even with --force."
	case checked && !matched:
		_ = gateway.RemovePID(pidPath)
		return gatewayUpProceed, pid, fmt.Sprintf("stale PID file recovered — pid %d does not look like a keylatch process; removed and starting fresh.", pid)
	default:
		// Inconclusive (review finding, warn-4): checked=false covers both
		// "the process legitimately died between IsRunning's probe and this
		// ps call" (safe to proceed) and "ps itself failed for an unrelated
		// reason — missing binary, sandboxed environment, permission issue —
		// while the original process is still alive and healthy" (NOT safe
		// to proceed: removing the PID file here would let a second gateway
		// start alongside a live one, with the PID file only tracking the
		// new instance). VerifyProcessIdentity gives no way to distinguish
		// these, so fail safe: refuse and never touch the PID file on
		// inconclusive evidence — require an explicit human decision instead
		// of guessing.
		return gatewayUpRefuse, pid, fmt.Sprintf("could not verify process identity for pid %d — refusing to remove its PID file on inconclusive evidence. If you have confirmed pid %d is not a keylatch process, stop it or delete %s yourself, then retry.", pid, pid, pidPath)
	}
}

// resolveAndValidateGatewayBindAddr wraps gateway.ResolveBindAddr with the
// same validateHostPort check used for KEYLATCH_GATEWAY_ADDR/
// KEYLATCH_PROXY_ADDR (docker-server-security hardening), so a malformed
// --listen/KEYLATCH_GATEWAY_LISTEN value produces a clean exitcode.UserError
// message here instead of a raw net.Listen error surfacing later inside
// gateway.New()/Serve().
//
// Kept as a standalone, side-effect-free function (rather than inlined in
// RunE) so it can be unit tested without starting a real server.
func resolveAndValidateGatewayBindAddr(port int, listenAddr string, unsafeBindAll bool, bindEnv llmcontext.Lookup) (bind string, allowExternal bool, err error) {
	bind, allowExternal = gateway.ResolveBindAddr(port, listenAddr, unsafeBindAll, bindEnv)
	if err := validateHostPort(bind); err != nil {
		return "", false, err
	}
	return bind, allowExternal, nil
}

// --- gateway down ---

// gatewayDownAction is the decision resolveGatewayDownAction returns to RunE.
type gatewayDownAction int

const (
	// gatewayDownProceed: process identity verification confirmed the PID
	// belongs to a keylatch process (or verification is unsupported on this
	// platform, or was overridden with --force) — safe to signal it.
	gatewayDownProceed gatewayDownAction = iota
	// gatewayDownStalePID: verification confirmed the PID does NOT belong to
	// a keylatch process — do not signal an unrelated process; just clean up
	// the stale PID file.
	gatewayDownStalePID
	// gatewayDownRefuse: verification was inconclusive and --force was not
	// given — refuse to signal on unverifiable evidence rather than risk
	// killing an unrelated process that happens to have reused the PID.
	gatewayDownRefuse
)

// resolveGatewayDownAction mirrors resolveGatewayUpRunning's process-identity
// verification (L2) for the stop path: IsRunning only signal-0-probes the
// pid, so a recycled pid can belong to a completely unrelated process by the
// time `gateway down` runs — sending SIGTERM there kills someone else's
// process instead of doing nothing. `gateway up --force` already gets this
// protection; `down` previously had none.
//
// Kept as a standalone, side-effect-isolated function (rather than inlined
// in RunE) so it is unit-testable with a mocked runner and without sending a
// real signal.
func resolveGatewayDownAction(ctx context.Context, pid int, pidPath string, force bool, runner kexec.CommandRunner, psBin string) (action gatewayDownAction, note string) {
	if runtime.GOOS == "windows" {
		// ps-based identity verification is unavailable on this platform;
		// behave as before (matches resolveGatewayUpRunning's Windows note,
		// which tells users `gateway down` still works unconditionally).
		return gatewayDownProceed, ""
	}

	matched, checked := gateway.VerifyProcessIdentity(ctx, runner, psBin, pid)
	switch {
	case checked && matched:
		return gatewayDownProceed, ""
	case checked && !matched:
		return gatewayDownStalePID, fmt.Sprintf(
			"pid %d does not look like a keylatch process (stale PID file) — not sending a signal to it; removing the stale PID file instead.", pid)
	default:
		if force {
			return gatewayDownProceed, fmt.Sprintf(
				"could not verify process identity for pid %d — proceeding anyway because --force was given.", pid)
		}
		return gatewayDownRefuse, fmt.Sprintf(
			"could not verify process identity for pid %d — refusing to signal it on inconclusive evidence. If you have confirmed pid %d is the keylatch gateway, retry with --force, or stop it yourself and remove %s.", pid, pid, pidPath)
	}
}

func newGatewayDownCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop the running gateway",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			pidPath := paths.GatewayPID(env)
			force, _ := c.Flags().GetBool("force")

			pid, running := gateway.IsRunning(pidPath)
			if !running {
				fmt.Fprintln(c.OutOrStdout(), "gateway: not running (no PID file)")
				return nil
			}

			action, note := resolveGatewayDownAction(c.Context(), pid, pidPath, force, kexec.DefaultRunner, kexec.Resolve("ps"))
			switch action {
			case gatewayDownStalePID:
				fmt.Fprintf(c.ErrOrStderr(), "gateway down: %s\n", note)
				if err := gateway.RemovePID(pidPath); err != nil {
					return fmt.Errorf("gateway down: %w", err)
				}
				return nil
			case gatewayDownRefuse:
				return fmt.Errorf("gateway down: %s", note)
			}
			if note != "" {
				fmt.Fprintf(c.OutOrStdout(), "gateway: %s\n", note)
			}

			if err := gateway.SendTerm(pidPath); err != nil {
				return fmt.Errorf("gateway down: %w", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "gateway: sent SIGTERM to %d\n", pid)
			return nil
		},
	}
	cmd.Flags().Bool("force", false, "signal the PID even when process identity could not be verified")
	return cmd
}

// --- gateway status ---

func newGatewayStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show gateway running state and routes (value-free)",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			pidPath := paths.GatewayPID(env)

			running := false
			pidStr := "n/a"
			if data, err := os.ReadFile(pidPath); err == nil {
				pid := string(data)
				for len(pid) > 0 && (pid[len(pid)-1] == '\n' || pid[len(pid)-1] == ' ') {
					pid = pid[:len(pid)-1]
				}
				pidStr = pid
				if p, err := strconv.Atoi(pid); err == nil {
					if proc, err := os.FindProcess(p); err == nil {
						if err := proc.Signal(syscall.Signal(0)); err == nil {
							running = true
						}
					}
				}
			}

			state := "stopped"
			if running {
				state = "running"
			}
			fmt.Fprintf(c.OutOrStdout(), "gateway: %s (pid: %s)\n", state, pidStr)

			// Show active token count (value-free).
			tokenPath := paths.GatewayTokens(env)
			toks, _ := token.List(token.ListOpts{}, tokenPath)
			fmt.Fprintf(c.OutOrStdout(), "gateway: active tokens: %d\n", len(toks))

			return nil
		},
	}
}

// --- gateway token ---

func newGatewayTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage gateway tokens",
	}
	cmd.AddCommand(newGatewayTokenCreateCmd())
	cmd.AddCommand(newGatewayTokenListCmd())
	cmd.AddCommand(newGatewayTokenRevokeCmd())
	return cmd
}

func newGatewayTokenCreateCmd() *cobra.Command {
	var (
		allow   []string
		ttlStr  string
		maxUses int
	)
	cmd := &cobra.Command{
		Use:   "create <actor>",
		Short: "Mint a new gateway token",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			actor := args[0]

			// Refuse MaxUses=0 inside LLM session (unlimited tokens not allowed from LLM).
			isLLM := llmcontext.IsLLMSession(env)
			if isLLM && maxUses == 0 {
				return fmt.Errorf("gateway token create: MaxUses=0 (unlimited) tokens are not allowed in LLM sessions")
			}

			ttl := 1 * time.Hour
			if ttlStr != "" {
				var err error
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("gateway token create: invalid --ttl: %w", err)
				}
			}

			// Load signing key.
			keyPath := paths.GatewaySigningKey(env)
			signingKey, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("gateway token create: read signing key: %w", err)
			}

			storePath := paths.GatewayTokens(env)
			spec := token.TokenSpec{
				Actor:        actor,
				Capabilities: allow,
				TTL:          ttl,
				MaxUses:      maxUses,
				LLMSession:   isLLM,
				StorePath:    storePath,
				SigningKey:   signingKey,
			}

			jwt, t, err := token.Mint(spec)
			if err != nil {
				return fmt.Errorf("gateway token create: %w", err)
			}

			// Print JWT once (never stored after this point).
			fmt.Fprintf(c.OutOrStdout(), "token: %s\n", jwt)
			fmt.Fprintf(c.OutOrStdout(), "id: %s\n", t.ID)
			fmt.Fprintf(c.OutOrStdout(), "accessor: %s\n", t.Accessor)
			fmt.Fprintf(c.OutOrStdout(), "expires: %s\n", t.ExpiresAt.Format(time.RFC3339))

			// Audit log.
			// Note: AuditLogger is wired below on best-effort basis.
			_ = jwt // used above for output

			return nil
		},
	}
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "capability to allow (e.g. openrouter.chat)")
	cmd.Flags().StringVar(&ttlStr, "ttl", "1h", "token TTL (e.g. 1h, 30m)")
	cmd.Flags().IntVar(&maxUses, "max-uses", 0, "maximum uses (0=unlimited)")
	return cmd
}

func newGatewayTokenListCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active gateway tokens (no JWT values)",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			storePath := paths.GatewayTokens(env)

			toks, err := token.List(token.ListOpts{}, storePath)
			if err != nil {
				return fmt.Errorf("gateway token list: %w", err)
			}

			if useJSON {
				b, _ := json.Marshal(toks)
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ACCESSOR\tACTOR\tCAPABILITIES\tEXPIRES\tLLM")
			for _, t := range toks {
				caps := "n/a"
				if len(t.Capabilities) > 0 {
					caps = ""
					for i, cap := range t.Capabilities {
						if i > 0 {
							caps += ","
						}
						caps += cap
					}
				}
				llmStr := "no"
				if t.LLMSession {
					llmStr = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					t.Accessor[:8]+"...",
					t.Actor,
					caps,
					t.ExpiresAt.Format(time.RFC3339),
					llmStr,
				)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}

func newGatewayTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a gateway token",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			storePath := paths.GatewayTokens(env)
			if err := token.Revoke(args[0], storePath); err != nil {
				return fmt.Errorf("gateway token revoke: %w", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "gateway: token %s revoked\n", args[0])
			return nil
		},
	}
}

// isGoRunArtifact returns true when the current executable looks like a
// temporary binary produced by `go run`. Under `go run`, the binary is placed
// in a system temp directory; its path contains the OS temp dir prefix and
// typically a "go-build" or "go-run" segment.
//
// Used to block `gateway --detach` when running via `go run`, where
// re-exec of a temp binary is unsafe (the binary may already be deleted or
// the session tied to the go run invocation).
func isGoRunArtifact() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	tmp := os.TempDir()
	if tmp == "" {
		return false
	}
	// Normalise separators for comparison.
	return strings.HasPrefix(exe, tmp)
}

// --- gateway logs ---

func newGatewayLogsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show gateway logs",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			logPath := paths.GatewayLog(env)

			f, err := os.Open(logPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(c.OutOrStdout(), "gateway: no log file found")
					return nil
				}
				return fmt.Errorf("gateway logs: open %q: %w", logPath, err)
			}
			defer f.Close() //nolint:errcheck // defer close of log file, error non-actionable in read path

			if !follow {
				_, err := io.Copy(c.OutOrStdout(), f)
				return err
			}

			// Tail mode.
			_, _ = io.Copy(c.OutOrStdout(), f)
			sc := bufio.NewScanner(f)
			for {
				for sc.Scan() {
					fmt.Fprintln(c.OutOrStdout(), sc.Text())
				}
				time.Sleep(500 * time.Millisecond)
			}
		},
	}
	cmd.Flags().BoolVar(&follow, "follow", false, "follow log output (tail mode)")
	return cmd
}
