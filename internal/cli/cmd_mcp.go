package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	keylatchmcp "github.com/keylatch/keylatch/internal/mcp"
	"github.com/spf13/cobra"
)

// newPhase3MCPCmd returns the Phase 3 `mcp` command.
//
// FIND-014: --unsafe-bind-all is NOT registered as a flag.
func newPhase3MCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the keylatch MCP server",
		RunE: func(c *cobra.Command, args []string) error {
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			stdio, _ := c.Flags().GetBool("stdio")
			port, _ := c.Flags().GetInt("port")

			transport := keylatchmcp.TransportStdio
			bind := ""
			if port > 0 {
				transport = keylatchmcp.TransportTCP
				bind = fmt.Sprintf("127.0.0.1:%d", port)
			} else if !stdio {
				transport = keylatchmcp.TransportStdio
			}

			s, err := keylatchmcp.New(keylatchmcp.ServerOptions{
				Transport: transport,
				Bind:      bind,
				StderrLog: true,
			})
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			// Log bind address to stderr (never log the session token).
			if transport == keylatchmcp.TransportTCP {
				slog.Info("keylatch mcp listening", "bind", bind, "transport", "tcp")
			}

			// Create a context that cancels on SIGTERM or interrupt.
			ctx, cancel := signal.NotifyContext(context.Background(),
				syscall.SIGTERM, os.Interrupt)
			defer cancel()

			if err := s.Serve(ctx, store, nil); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}
			return nil
		},
	}
	// FIND-014: --unsafe-bind-all is explicitly NOT registered here.
	cmd.Flags().Bool("stdio", false, "use stdio transport (default)")
	cmd.Flags().Int("port", 0, "TCP port to listen on (127.0.0.1 only)")
	return cmd
}
