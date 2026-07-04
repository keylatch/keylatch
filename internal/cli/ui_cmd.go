// Package cli — Phase 10 UI subcommand.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/ui"
	"github.com/spf13/cobra"
)

// newUICmd returns the `keylatch ui` subcommand.
func newUICmd() *cobra.Command {
	var (
		port          int
		demo          bool
		noOpen        bool
		unsafeBindAll bool
		listenAddr    string
		scopeStr      string
	)

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Start the local browser UI for keylatch",
		Long: `Start a local HTTP server that serves the keylatch browser UI.

The server binds only to 127.0.0.1 by default. A one-time bootstrap URL is
printed to stdout; opening it in a browser exchanges the token for a session
cookie and redirects to the main UI.

Container reachability: --listen (or KEYLATCH_UI_LISTEN) explicitly opts in
to a non-loopback bind address, e.g. for Docker port-forwarding. This does
NOT weaken the default: it is an explicit, documented opt-in, and it is
still refused outright in LLM sessions (see below). Recommended container
usage: -e KEYLATCH_UI_LISTEN=0.0.0.0:7890.

Security notes:
  - When CLAUDE_CODE=1 (or any LLM session signal) is set, the scope is
    locked to status-only and write endpoints are not mounted (return 404).
  - --unsafe-bind-all and --listen/KEYLATCH_UI_LISTEN are both ignored in
    LLM sessions — non-loopback binds are refused unconditionally.
  - --scope=token-minting must be explicitly requested for token minting.`,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			isLLM := llmcontext.IsLLMSession(env)

			// Parse scope.
			scope, err := ui.ParseScope(scopeStr)
			if err != nil {
				return fmt.Errorf("ui: --scope: %w", err)
			}

			// bindEnv is used only to resolve the bind address (KEYLATCH_UI_LISTEN
			// lookup below). It must NOT replace env: opts.Env below is passed to
			// ui.New(), which re-derives IsLLMSession from it — swapping in a
			// no-op lookup there would incorrectly flip that check to "not an LLM
			// session" and defeat the fail-closed guarantee (New() also enforces
			// this independently, but the CLI's own messaging must stay accurate).
			bindEnv := env

			// LLM session ceiling: override scope to status-only.
			if isLLM {
				if scope > ui.ScopeStatusOnly {
					fmt.Fprintln(c.ErrOrStderr(), "ui: LLM session detected — scope locked to status-only")
				}
				scope = ui.ScopeStatusOnly
				if unsafeBindAll {
					fmt.Fprintln(c.ErrOrStderr(), "ui: LLM session detected — --unsafe-bind-all ignored")
					unsafeBindAll = false
				}
				if listenAddr != "" || env(ui.EnvListenKey) != "" {
					fmt.Fprintln(c.ErrOrStderr(), "ui: LLM session detected — --listen/KEYLATCH_UI_LISTEN ignored")
					listenAddr = ""
					// New() refuses any non-loopback bind in an LLM session
					// regardless; suppress the env-var lookup here purely so the
					// address we print/attempt to bind is 127.0.0.1, matching the
					// message above.
					bindEnv = func(string) string { return "" }
				}
			}

			bind, allowExternalBind, bindErr := resolveAndValidateUIBindAddr(port, listenAddr, unsafeBindAll, bindEnv)
			if bindErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "ui: %v\n", bindErr)
				os.Exit(exitcode.UserError)
			}
			unsafeBindAll = unsafeBindAll || allowExternalBind

			// Generate signing key.
			signingKey := make([]byte, 32)
			if _, err := rand.Read(signingKey); err != nil {
				return fmt.Errorf("ui: generate signing key: %w", err)
			}

			// Generate IPC secret for POST /v1/receipts (S-INV-12).
			ipcSecretRaw := make([]byte, 32)
			if _, err := rand.Read(ipcSecretRaw); err != nil {
				return fmt.Errorf("ui: generate IPC secret: %w", err)
			}
			ipcSecret := hex.EncodeToString(ipcSecretRaw)

			opts := ui.ServerOptions{
				Bind:              bind,
				SigningKey:        signingKey,
				Scope:             scope,
				Demo:              demo,
				AllowExternalBind: unsafeBindAll,
				Env:               env,
				IPCSecret:         ipcSecret,
			}

			srv, err := ui.New(opts)
			if err != nil {
				return fmt.Errorf("ui: %w", err)
			}

			bootstrapURL := srv.BootstrapURL()
			fmt.Fprintf(c.OutOrStdout(), "keylatch ui: open this URL in your browser:\n\n  %s\n\n", bootstrapURL)

			if !noOpen {
				// Attempt to open browser (best-effort; ignore errors).
				_ = openBrowser(bootstrapURL)
			}

			if demo {
				fmt.Fprintln(c.OutOrStdout(), "keylatch ui: demo mode — using stub data")
			}
			if isLLM {
				fmt.Fprintln(c.OutOrStdout(), "keylatch ui: scope=status-only (LLM session)")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer cancel()

			fmt.Fprintf(c.OutOrStdout(), "keylatch ui: listening on %s\n", bind)
			return srv.Serve(ctx)
		},
	}

	cmd.Flags().IntVar(&port, "port", 7890, "port to listen on")
	cmd.Flags().BoolVar(&demo, "demo", false, "run in demo mode with stub data")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not attempt to open browser automatically")
	cmd.Flags().BoolVar(&unsafeBindAll, "unsafe-bind-all", false, "bind to 0.0.0.0 (non-LLM sessions only)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "explicit non-loopback bind address, e.g. 0.0.0.0:7890 (Docker; non-LLM sessions only; overrides KEYLATCH_UI_LISTEN)")
	cmd.Flags().StringVar(&scopeStr, "scope", "admin", "session scope: status-only|setup|admin|token-minting")

	return cmd
}

// resolveAndValidateUIBindAddr wraps ui.ResolveBindAddr with the same
// validateHostPort check used for KEYLATCH_GATEWAY_ADDR/KEYLATCH_PROXY_ADDR
// (docker-server-security hardening), so a malformed --listen/
// KEYLATCH_UI_LISTEN value produces a clean exitcode.UserError message here
// instead of a raw net.Listen error surfacing later inside ui.New()/Serve().
//
// Kept as a standalone, side-effect-free function (rather than inlined in
// RunE) so it can be unit tested without starting a real server.
func resolveAndValidateUIBindAddr(port int, listenAddr string, unsafeBindAll bool, bindEnv llmcontext.Lookup) (bind string, allowExternal bool, err error) {
	bind, allowExternal = ui.ResolveBindAddr(port, listenAddr, unsafeBindAll, bindEnv)
	if err := validateHostPort(bind); err != nil {
		return "", false, err
	}
	return bind, allowExternal, nil
}

// openBrowser attempts to open url in the system browser. Best-effort.
func openBrowser(url string) error {
	candidates := []string{"open", "xdg-open"}
	for _, bin := range candidates {
		c := exec.Command(bin, url) //nolint:gosec // url is our own server URL
		c.Stdout = nil
		c.Stderr = nil
		if err := c.Start(); err == nil {
			// Reap in background so we don't block.
			go func() { _ = c.Wait() }()
			return nil
		}
	}
	// Windows fallback.
	c := exec.Command("cmd", "/c", "start", url) //nolint:gosec
	_ = c.Start()
	return nil
}

// Approve/deny/recipes stubs — wired to root from ui_cmd_stubs.go.

// newUIRecipesCmd is a stub for `keylatch recipes`.
func newUIRecipesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recipes",
		Short: "Show common keylatch usage recipes (Phase 10 stub)",
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), "recipes: coming soon in a future phase")
			return nil
		},
	}
}
