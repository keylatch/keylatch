// Package cli — Phase 10 UI subcommand.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"os/signal"
	"syscall"

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
		scopeStr      string
	)

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Start the local browser UI for keylatch",
		Long: `Start a local HTTP server that serves the keylatch browser UI.

The server binds only to 127.0.0.1 by default. A one-time bootstrap URL is
printed to stdout; opening it in a browser exchanges the token for a session
cookie and redirects to the main UI.

Security notes:
  - When CLAUDE_CODE=1 (or any LLM session signal) is set, the scope is
    locked to status-only and write endpoints are not mounted (return 404).
  - --unsafe-bind-all is ignored in LLM sessions.
  - --scope=token-minting must be explicitly requested for token minting.`,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			isLLM := llmcontext.IsLLMSession(env)

			// Parse scope.
			scope, err := ui.ParseScope(scopeStr)
			if err != nil {
				return fmt.Errorf("ui: --scope: %w", err)
			}

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
			}

			bind := fmt.Sprintf("127.0.0.1:%d", port)
			if unsafeBindAll {
				bind = fmt.Sprintf("0.0.0.0:%d", port)
			}

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
	cmd.Flags().StringVar(&scopeStr, "scope", "admin", "session scope: status-only|setup|admin|token-minting")

	return cmd
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

// newUIRecipesCmd returns the `keylatch recipes` command with common usage patterns.
func newUIRecipesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recipes",
		Short: "Show common keylatch usage recipes",
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			fmt.Fprintln(w, "Common recipes:")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Run a command with credentials injected:")
			fmt.Fprintln(w, "    keylatch run openrouter -- curl https://api.openrouter.ai/...")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Connect a provider:")
			fmt.Fprintln(w, "    keylatch connect openrouter")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Check health:")
			fmt.Fprintln(w, "    keylatch doctor")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Install agent guard:")
			fmt.Fprintln(w, "    keylatch install-guard claude-code")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  Start the gateway:")
			fmt.Fprintln(w, "    keylatch gateway up")
			return nil
		},
	}
}
