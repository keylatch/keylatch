// Package main is the keylatchd sidecar entry point.
//
// keylatchd wraps the keylatch UI server with additional
// desktop-shell integration: HMAC-authenticated IPC over a Unix socket,
// FD-based key ingestion, and LLM-session gating.
//
// Normal invocation (backwards-compatible):
//
//	keylatchd [--port <n>] [--demo] ...
//
// Desktop-shell invocation (from Tauri shell only):
//
//	keylatchd --from-desktop-shell --ipc-socket <path>
//	KEYLATCH_IPC_KEY_FD=<n> (inherited file descriptor)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/sidecar/ipc"
	"github.com/keylatch/keylatch/internal/ui"
	"github.com/spf13/cobra"
)

// buildVersion is injected at build time via -ldflags.
var buildVersion = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		fromDesktopShell bool
		ipcSocket        string
		port             int
		demo             bool
		logLevel         string
	)

	cmd := &cobra.Command{
		Use:   "keylatchd",
		Short: "Keylatch UI server (desktop sidecar or standalone)",
		Long: `keylatchd is the keylatch UI server.

When launched by the Tauri desktop shell, pass --from-desktop-shell and
--ipc-socket. The HMAC key for IPC authentication is passed via the file
descriptor numbered in the KEYLATCH_IPC_KEY_FD environment variable —
never via a file path or command-line flag.

When run without --from-desktop-shell, behaviour is identical to
		"keylatch ui" (backwards-compatible).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var level slog.Level
			switch strings.ToLower(logLevel) {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "error":
				level = slog.LevelError
			default:
				level = slog.LevelWarn
			}
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			hardenProcess()

			env := llmcontext.DefaultLookup

			// If an LLM session is detected in desktop-shell mode,
			// refuse to start the value-bearing UI and exit cleanly.
			if fromDesktopShell && llmcontext.IsLLMSession(env) {
				slog.Warn("LLM session detected; use the keylatch CLI instead")
				return nil
			}

			// heap-dump canary check.
			// On Linux: scan /proc/self/mem for residual sensitive patterns.
			// On macOS/Windows: log that OS-level protection is in effect.
			logHeapDumpProtectionStatus()

			// §2.6: first-launch notification and stdout hint.
			// Load daemon state; if this is the first start, fire the notification.
			statePath := paths.DaemonState(env)
			daemonState, _ := daemon.LoadState(statePath) // best-effort; ignore parse errors
			if !daemonState.FirstLaunchDone {
				// Print the "get started" hint to stdout (§2.6).
				fmt.Fprintln(os.Stdout, "Get started: keylatch.dev/start")

				// Send the macOS user notification (no-op on non-darwin).
				daemon.SendFirstLaunchNotification()

				// Mark first launch as done.
				daemonState.FirstLaunchDone = true
				// Best-effort: if state write fails, notification will fire again next
				// start — acceptable; it is not a security concern.
				_ = daemon.SaveState(statePath, daemonState)
			}

			// Read HMAC key from inherited FD.
			var hmacKey []byte
			if fromDesktopShell {
				if ipcSocket == "" {
					return fmt.Errorf("keylatchd: --ipc-socket is required with --from-desktop-shell")
				}
				var err error
				hmacKey, err = readHMACKeyFromFD()
				if err != nil {
					return fmt.Errorf("keylatchd: IPC key ingestion: %w", err)
				}
			}

			// Generate a signing key for the UI session.
			signingKey := make([]byte, 32)
			if _, err := rand.Read(signingKey); err != nil {
				return fmt.Errorf("keylatchd: generate signing key: %w", err)
			}

			// Generate IPC secret for POST /v1/receipts.
			ipcSecretRaw := make([]byte, 32)
			if _, err := rand.Read(ipcSecretRaw); err != nil {
				return fmt.Errorf("keylatchd: generate IPC secret: %w", err)
			}
			ipcSecret := hex.EncodeToString(ipcSecretRaw)

			opts := ui.ServerOptions{
				Bind:       fmt.Sprintf("127.0.0.1:%d", port),
				SigningKey: signingKey,
				Scope:      ui.ScopeAdmin,
				Demo:       demo,
				Env:        env,
				IPCSecret:  ipcSecret,
			}
			srv, err := ui.New(opts)
			if err != nil {
				return fmt.Errorf("keylatchd: ui server: %w", err)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer cancel()

			// Start audit retention sweep goroutine.
			// Load config for audit retention settings; fall back to defaults on error.
			auditCfg := config.Default().Audit
			if cfg, err := config.Load(paths.Config(env)); err == nil {
				auditCfg = cfg.Audit
			}
			retentionDays := audit.LoadRetentionDays(auditCfg)
			sweepHours := audit.LoadSweepIntervalHours(auditCfg)
			audit.StartRetentionSweepLoop(ctx, paths.Audit(env), retentionDays, sweepHours)

			// Start IPC server if in desktop-shell mode.
			if fromDesktopShell {
				ipcServer, startErr := ipc.NewServer(ipcSocket, hmacKey)
				if startErr != nil {
					return fmt.Errorf("keylatchd: IPC server: %w", startErr)
				}
				// Zero the key material from the local slice — the server
				// has copied what it needs.
				for i := range hmacKey {
					hmacKey[i] = 0
				}
				go func() {
					if listenErr := ipcServer.Listen(ctx); listenErr != nil {
						slog.Error("IPC server error", "error", listenErr)
					}
				}()

				// Emit ready signal to the parent Tauri shell on stdout.
				// The Tauri shell parses this line to learn the server URL.
				ready := map[string]string{
					"event": "ready",
					"url":   srv.BootstrapURL(),
					"build": buildVersion,
				}
				if encErr := json.NewEncoder(os.Stdout).Encode(ready); encErr != nil {
					return fmt.Errorf("keylatchd: emit ready: %w", encErr)
				}
			}

			return srv.Serve(ctx)
		},
	}

	cmd.Flags().BoolVar(&fromDesktopShell, "from-desktop-shell", false,
		"Enable desktop-shell integration (IPC + FD key ingestion)")
	cmd.Flags().StringVar(&ipcSocket, "ipc-socket", "",
		"Unix socket path for IPC (required with --from-desktop-shell)")
	cmd.Flags().IntVar(&port, "port", 7890, "Port for the UI HTTP server")
	cmd.Flags().BoolVar(&demo, "demo", false, "Run in demo mode with stub data")
	cmd.AddCommand(newServeCmd())
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "log verbosity: debug|info|warn|error")

	return cmd
}

func newServeCmd() *cobra.Command {
	var socket, binary, sshAgentSocket string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the control socket used by the keylatch thin client",
		Long: `serve listens on a Unix socket that only the current user can open.
The keylatch client holds no key material; it sends requests here and the
daemon, which owns the vault, signing keys and policy, decides what the
caller may have. Run it from your own terminal or a user service, outside
any agent sandbox.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hardenProcess()
			env := llmcontext.DefaultLookup
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			if err := registry.InitFromConfig(ctx, env); err != nil {
				return fmt.Errorf("keylatchd: registry: %w", err)
			}
			if binary == "" {
				resolved, err := siblingKeylatch()
				if err != nil {
					return err
				}
				binary = resolved
			}
			if socket == "" {
				socket = paths.ControlSocket(env)
			}
			ln, err := control.Listen(socket)
			if err != nil {
				return fmt.Errorf("keylatchd: %w", err)
			}
			defer func() { _ = os.Remove(socket) }()
			fmt.Fprintf(cmd.OutOrStdout(), "keylatchd: listening on %s\n", socket)

			emitter, closeAudit, err := cli.OpenAuditEmitter()
			if err != nil {
				return fmt.Errorf("keylatchd: the audit log cannot be opened, and Keylatch does not serve without an audit trail: %w", err)
			}
			defer closeAudit()
			cfg := control.Config{Env: env, Binary: binary, Audit: emitter, SigningKey: func() ([]byte, error) {
				return cli.LoadGatewaySigningKey(env, false)
			}}
			if mgr, mintCred, release, err := newPlaceholders(env); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "keylatchd: placeholder tier unavailable: %v\n", err)
			} else {
				defer release()
				cfg.Placeholders = mgr
				cfg.Mint = mintCred
			}
			cfg.Decide = enforce.Decide
			cfg.Approve = newApprover(env, emitter)
			cfg.Contained = newContained(socket, binary, vaultResolver{cfg: loadConfig(env), env: env, log: emitter})
			var agentLn *net.UnixListener
			if keys, admin, closeAudit, err := newKeyService(env); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "keylatchd: key operations are disabled: %v\n", err)
			} else {
				defer closeAudit()
				cfg.Keys, cfg.KeyAdmin = keys, admin
				if sshAgentSocket != "off" {
					if sshAgentSocket == "" {
						sshAgentSocket = paths.SSHAgentSocket(env)
					}
					if agentLn, err = control.Listen(sshAgentSocket); err != nil {
						return fmt.Errorf("keylatchd: ssh-agent: %w", err)
					}
					defer func() { _ = os.Remove(sshAgentSocket) }()
					fmt.Fprintf(cmd.OutOrStdout(), "keylatchd: ssh-agent on %s\n", sshAgentSocket)
				}
			}
			srv := control.NewServer(cfg)
			if agentLn != nil {
				go func() { _ = srv.ServeSSHAgent(ctx, agentLn) }()
			}
			return srv.Serve(ctx, ln)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "control socket path (default: $KEYLATCH_SOCKET or $XDG_RUNTIME_DIR/keylatch/keylatchd.sock)")
	cmd.Flags().StringVar(&binary, "keylatch-bin", "", "keylatch executable the daemon runs for served verbs (default: next to keylatchd)")
	cmd.Flags().StringVar(&sshAgentSocket, "ssh-agent-socket", "", "ssh-agent endpoint path (default: $KEYLATCH_SSH_AGENT_SOCKET or ssh-agent.sock next to the control socket; \"off\" disables it)")
	return cmd
}

func loadConfig(env llmcontext.Lookup) config.Config {
	if cfg, err := config.Load(paths.Config(env)); err == nil {
		return cfg
	}
	return config.Default()
}

// newKeyService wires key operations to the configured backend, the sealed
// key operation allowlist and the audit log. Without an audit log they stay off.
func newKeyService(env llmcontext.Lookup) (*keyops.Service, *keyops.Admin, func(), error) {
	cfg, err := config.Load(paths.Config(env))
	if err != nil {
		cfg = config.Default()
	}
	store, err := keyops.OpenStore(env)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("allowlist: %w", err)
	}
	emitter, closeAudit, err := cli.OpenAuditEmitter()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("audit log: %w", err)
	}
	svc, err := keyops.New(store, keyops.NewBackendKeys(cfg, env), emitter)
	if err == nil {
		var admin *keyops.Admin
		if admin, err = keyops.NewAdmin(store, emitter); err == nil {
			return svc, admin, closeAudit, nil
		}
	}
	closeAudit()
	return nil, nil, nil, err
}

func siblingKeylatch() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("keylatchd: locate keylatch executable: %w; pass --keylatch-bin", err)
	}
	sibling := filepath.Join(filepath.Dir(self), "keylatch")
	if info, err := os.Stat(sibling); err != nil || info.IsDir() {
		return "", fmt.Errorf("keylatchd: no keylatch executable next to %s; pass --keylatch-bin", self)
	}
	return sibling, nil
}

// readHMACKeyFromFD reads exactly 32 bytes from the file descriptor
// identified by the KEYLATCH_IPC_KEY_FD environment variable.
// The FD is closed immediately after reading.
// The caller is responsible for zeroing the returned slice after use.
func readHMACKeyFromFD() ([]byte, error) {
	fdStr := os.Getenv("KEYLATCH_IPC_KEY_FD")
	if fdStr == "" {
		return nil, fmt.Errorf("KEYLATCH_IPC_KEY_FD is not set; " +
			"HMAC key must be passed via an inherited file descriptor")
	}
	fdNum, err := strconv.Atoi(fdStr)
	if err != nil {
		return nil, fmt.Errorf("KEYLATCH_IPC_KEY_FD=%q is not a valid file descriptor number: %w", fdStr, err)
	}

	// Wrap the inherited FD in an os.File so we can read from it.
	// NewFile does not close the underlying fd.
	f := os.NewFile(uintptr(fdNum), "ipc-key-fd")
	if f == nil {
		return nil, fmt.Errorf("file descriptor %d is not valid", fdNum)
	}

	// N4: validate that the FD is actually a pipe (not a regular file or device).
	info, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat KEYLATCH_IPC_KEY_FD %d: %w", fdNum, statErr)
	}
	if info.Mode()&os.ModeNamedPipe == 0 && info.Mode()&os.ModeCharDevice == 0 {
		_ = f.Close()
		return nil, fmt.Errorf("KEYLATCH_IPC_KEY_FD %d is not a pipe (mode: %v)", fdNum, info.Mode())
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(f, key); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("reading 32-byte HMAC key from fd %d: %w", fdNum, err)
	}

	// Close the FD immediately — it must not remain open after key ingestion.
	if err := f.Close(); err != nil {
		// Non-fatal: key was read; log and continue.
		slog.Warn("closing IPC key FD failed", "fd", fdNum, "error", err)
	}

	// Clear the env var so it is not visible to any subprocesses we might fork.
	_ = os.Unsetenv("KEYLATCH_IPC_KEY_FD")

	return key, nil
}
