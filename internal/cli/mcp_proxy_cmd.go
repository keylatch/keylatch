package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/mcpproxy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

func newMCPProxyCmd() *cobra.Command {
	var url, namespace string
	cmd := &cobra.Command{
		Use:   "proxy <connection> --url <remote MCP URL>",
		Short: "Serve a remote MCP server to an agent without giving the agent its token",
		Long: `proxy is an MCP stdio server for agent clients. It forwards each message to
the remote MCP server at --url and adds the connection's token as the
Authorization header its header slot names, so the client's configuration
holds a connection name and a URL and no token.

The URL's host must be one the connection's header slot is bound to, and it
must use https. Redirects are not followed. The connection's policy is
checked before the first request, every request is written to the audit log,
and an answer that repeats the token is redacted.

Add it to a client as an MCP server whose command is
  keylatch mcp proxy <connection> --url <remote MCP URL>

Example:
  keylatch connect remote-mcp --provider custom --host mcp.example.com:443 \
    --slot header:Authorization:Bearer --env REMOTE_MCP_TOKEN
  keylatch mcp proxy remote-mcp --url https://mcp.example.com/mcp`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runMCPProxy(c, args[0], url, namespace)
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "remote MCP server endpoint (required)")
	cmd.Flags().StringVar(&namespace, "namespace", "default", "vault namespace of the connection")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func runMCPProxy(c *cobra.Command, connection, url, namespace string) error {
	env := llmcontext.DefaultLookup
	store := newDispatchedStore(loadCLIConfig(c), env)
	binding, secretPath, err := mcpProxyBinding(c.Context(), store, connection, namespace)
	if err != nil {
		return NewUsageError("mcp proxy: %s declares no host bindings: %v", connection, err)
	}
	auditLog, cleanup, err := requireAuditLogger("mcp proxy")
	if err != nil {
		return err
	}
	defer cleanup()

	// stdin carries the client's messages, so it never says whether a person
	// is at the terminal.
	caller := callerkind.Local(env, false).Kind
	ctx, stop := signal.NotifyContext(c.Context(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	err = mcpproxy.Run(ctx, mcpproxy.Config{
		URL: url, Connection: connection, Binding: binding,
		Secret: func(ctx context.Context, field string) ([]byte, error) {
			v, _, err := store.Get(ctx, secretPath(field))
			if errors.Is(err, backend.ErrNotFound) {
				return nil, nil
			}
			return v, err
		},
		Authorize: func(ctx context.Context) error {
			d := ciScopedEnforce(enforce.Decide)(ctx, enforce.Request{
				Connection: connection, Namespace: namespace, Caller: caller,
			})
			if !d.Allow || d.ApprovalRequired {
				return NewPolicyDeny("mcp proxy: %s", denialReason(d))
			}
			return nil
		},
		Caller: caller,
		Audit:  audit.AsEmitter(auditLog),
	}, c.InOrStdin(), c.OutOrStdout())
	if err != nil {
		var cliErr *CLIError
		if errors.As(err, &cliErr) {
			return err
		}
		return NewUsageError("mcp proxy: %v", err)
	}
	return nil
}

// mcpProxyBinding finds where the connection is bound and where its fields
// live: a template's bindings, or the binding of a custom connection.
func mcpProxyBinding(ctx context.Context, store connections.Store, connection, namespace string) (registry.Binding, func(string) string, error) {
	if tmpl, err := registry.Get(connection); err == nil {
		b, err := registry.BindingFor(connection)
		return b, func(field string) string {
			return connections.SecretFieldPath(namespace, tmpl.Category, connection, field)
		}, err
	}
	b, err := connections.CustomBindingFor(ctx, store, namespace, connection)
	return b, func(field string) string { return connections.CustomSecretPath(namespace, connection, field) }, err
}

func denialReason(d enforce.Decision) string {
	switch {
	case d.Reason != "":
		return d.Reason
	case d.ApprovalRequired:
		return "the connection's policy needs an approval this command cannot collect"
	}
	return fmt.Sprintf("the connection's policy denies the request (source %s)", d.Source)
}
