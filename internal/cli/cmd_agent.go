package cli

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/agent"
	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// newPhase3AgentCmd returns the `agent` subcommand group.
func newPhase3AgentCmd() *cobra.Command {
	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage AI agent integrations",
	}
	agentCmd.AddCommand(newAgentSetupCmd())
	agentCmd.AddCommand(newAgentSnippetCmd())
	return agentCmd
}

// newAgentSetupCmd returns the `agent setup` command.
func newAgentSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup <agent>",
		Short: "Install keylatch integration for an AI agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			modeStr, _ := c.Flags().GetString("mode")
			dryRun, _ := c.Flags().GetBool("dry-run")
			force, _ := c.Flags().GetBool("force")
			diff, _ := c.Flags().GetBool("diff")
			namespace, _ := c.Flags().GetString("namespace")

			mode := agentsnippet.ProfileMode(modeStr)
			if mode == "" {
				mode = agentsnippet.ProfileModeMCP
			}

			// Gate --force on !IsLLMSession() (S3-11).
			if force && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Error: --force is not permitted inside an LLM session")
				os.Exit(exitcode.SecurityBlock)
			}

			preset, err := agent.Get(args[0])
			if err != nil {
				// P1.3: actionable error for unknown/undetected agents.
				agentName := args[0]
				home, homeErr := os.UserHomeDir()
				configDir := "~/.claude/"
				if homeErr == nil {
					configDir = home + "/.claude/"
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: agent %q not found.\n\n", agentName)
				if agentName == "claude-code" {
					fmt.Fprintf(c.ErrOrStderr(), "  Claude Code config dir not found at %s\n", configDir)
					fmt.Fprintln(c.ErrOrStderr(), "  Install Claude Code first: https://claude.ai/download")
					fmt.Fprintln(c.ErrOrStderr())
				} else {
					fmt.Fprintf(c.ErrOrStderr(), "  %v\n\n", err)
				}
				fmt.Fprintln(c.ErrOrStderr(), "  Supported agents: claude-code, codex, cursor, openhands, opencode")
				os.Exit(exitcode.UserError)
			}

			opts := agent.SetupOptions{
				Mode:      mode,
				DryRun:    dryRun,
				Force:     force,
				Namespace: namespace,
			}

			if diff {
				d, err := preset.Diff(ctx, opts, store)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
				if d.Content != "" {
					fmt.Fprintln(c.OutOrStdout(), d.Content)
				} else {
					fmt.Fprintln(c.OutOrStdout(), "No changes.")
				}
				return nil
			}

			receipt, err := preset.Setup(ctx, opts, store)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
			}

			for _, f := range receipt.FilesWritten {
				fmt.Fprintf(c.OutOrStdout(), "Written: %s\n", f)
			}
			if receipt.Instructions != "" {
				fmt.Fprintln(c.OutOrStdout(), "\n"+receipt.Instructions)
			}
			return nil
		},
	}
	cmd.Flags().String("mode", "mcp", "profile mode: mcp|run|gateway")
	cmd.Flags().Bool("dry-run", false, "show what would be changed without writing files (S3-7)")
	cmd.Flags().Bool("force", false, "overwrite existing config (blocked inside LLM sessions)")
	cmd.Flags().Bool("diff", false, "show diff against current config")
	cmd.Flags().String("namespace", "default", "vault namespace")
	return cmd
}

// newAgentSnippetCmd returns the `agent snippet` command.
func newAgentSnippetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snippet",
		Short: "Print the agent instruction snippet",
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			format, _ := c.Flags().GetString("format")

			switch format {
			case "prose", "":
				snippet, err := agentsnippet.GenerateInstruction(ctx, agentsnippet.InstructionOpts{
					IncludeMCP: true,
				}, store)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
				fmt.Fprint(c.OutOrStdout(), snippet)

			case "mcp-json":
				mcpCfg, err := agentsnippet.GenerateMCPConfig(ctx)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
				printJSON(c.OutOrStdout(), mcpCfg)

			case "both":
				snippet, err := agentsnippet.GenerateInstruction(ctx, agentsnippet.InstructionOpts{
					IncludeMCP: true,
				}, store)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error (prose): %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
				fmt.Fprint(c.OutOrStdout(), snippet)
				fmt.Fprint(c.OutOrStdout(), "\n---\n")
				mcpCfg, err := agentsnippet.GenerateMCPConfig(ctx)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error (mcp-json): %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
				printJSON(c.OutOrStdout(), mcpCfg)

			default:
				fmt.Fprintf(c.ErrOrStderr(), "Unknown format %q; use prose, mcp-json, or both\n", format)
				os.Exit(exitcode.UserError)
			}

			return nil
		},
	}
	cmd.Flags().String("format", "prose", "output format: prose|mcp-json|both")
	return cmd
}
