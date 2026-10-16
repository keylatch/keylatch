package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/explain"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/actor"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
)

// newExplainCmd returns the `keylatch explain` group. It reads the policy and
// provider templates only, never a vault, so it is safe in any session.
func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain whether a run is allowed and how its secret would be delivered",
		Long: `Explain answers "may this run, and how?" without running anything.

It reports the delivery tier that would be chosen, whether approval is needed,
the hosts and scope that apply, where the child process runs and the residual
risk. It never reads or prints secret values. Use --json for the stable,
versioned document that host guards consume; 'keylatch explain schema' prints
its JSON Schema.`,
	}
	cmd.AddCommand(newExplainRunCmd(), newExplainPolicyCmd(), newExplainSchemaCmd())
	return cmd
}

func newExplainRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <connection> -- <command> [args...]",
		Short: "Explain a keylatch run without executing it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			connection, argv, err := parseRunArgs(args)
			if err != nil {
				return NewUsageError("%v", err)
			}
			lookup := llmcontext.DefaultLookup
			pol, err := loadExplainPolicy(lookup)
			if err != nil {
				return err
			}
			actorName, _ := c.Flags().GetString("actor")
			if actorName == "" {
				actorName = actor.Infer(lookup).Name
			}
			cwd, _ := c.Flags().GetString("cwd")
			if cwd == "" {
				cwd, _ = os.Getwd()
			}
			tier, _ := c.Flags().GetString("tier")

			rep := explain.Run(explain.Input{
				Policy:     pol,
				Manifest:   manifest.Current(),
				Connection: resolveConnection(c.Context(), connection),
				Document:   explainDocument(c.Context()),
				Request: explain.Request{
					Actor:      actorName,
					LLMSession: llmcontext.IsLLMSession(lookup),
					Connection: connection,
					Argv:       argv,
					CWD:        cwd,
					Tier:       strings.ToUpper(tier),
				},
			})
			if wantJSON(c) {
				return writeJSON(c.OutOrStdout(), rep)
			}
			return writeRunText(c.OutOrStdout(), rep)
		},
	}
	cmd.Flags().String("actor", "", "evaluate as this actor instead of the inferred one")
	cmd.Flags().String("cwd", "", "evaluate for this working directory (default: current directory)")
	cmd.Flags().String("tier", "", "ask about a specific delivery tier (D1..D6); never relaxes policy")
	return cmd
}

func newExplainPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy [connection]",
		Short: "Explain the effective policy per caller",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			pol, err := loadExplainPolicy(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			in := explain.PolicyInput{Policy: pol, Manifest: manifest.Current(), Resolve: func(name string) explain.Connection { return resolveConnection(c.Context(), name) }, Document: explainDocument(c.Context())}
			if docs, err := (connpolicy.Store{Dir: paths.PolicyDir(llmcontext.DefaultLookup)}).LoadAll(); err == nil {
				in.DocumentConnections = connpolicy.Connections(docs)
			}
			if len(args) == 1 {
				in.Connection = args[0]
			}
			in.Actor, _ = c.Flags().GetString("actor")
			rep := explain.Effective(in)
			if wantJSON(c) {
				return writeJSON(c.OutOrStdout(), rep)
			}
			return writePolicyText(c.OutOrStdout(), rep)
		},
	}
	cmd.Flags().String("actor", "", "report for this actor only")
	return cmd
}

func newExplainSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of the explain output",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			_, err := c.OutOrStdout().Write(explain.Schema())
			return err
		},
	}
}

func wantJSON(c *cobra.Command) bool {
	v, _ := c.Flags().GetBool("json")
	return v
}

// explainDocument answers from the connection policy documents through the
// same enforcement point run and call use. It reports false when no document
// governs the request, so the rules file decides.
func explainDocument(ctx context.Context) explain.DocumentFunc {
	return func(req explain.Request, kind, runtime string) (explain.Verdict, bool) {
		argv := req.Argv
		if len(argv) == 1 && argv[0] == "-" { // the placeholder explain policy uses, not a program
			argv = nil
		}
		d := enforce.Decide(ctx, enforce.Request{
			Connection: req.Connection,
			Runtime:    runtime,
			Caller:     callerkind.Kind(kind),
			Actor:      req.Actor,
			Command:    argv,
			CWD:        req.CWD,
		})
		if d.Source != "connection-policy" && d.Source != "fallback-policy" {
			return explain.Verdict{}, false
		}
		return explain.Verdict{Allow: d.Allow, ApprovalRequired: d.ApprovalRequired, Reason: d.Reason, SafeFix: d.SafeFix}, true
	}
}

func loadExplainPolicy(lookup llmcontext.Lookup) (policy.Policy, error) {
	p, err := policy.Load(paths.Policy(lookup))
	switch {
	case err == nil:
		return p, nil
	case errors.Is(err, os.ErrNotExist):
		return policy.Policy{SchemaVersion: policy.SchemaVersion, Mode: policy.ModeEnforcing, DefaultDeny: true}, nil
	default:
		return policy.Policy{}, fmt.Errorf("explain: %w", err)
	}
}

// resolveConnection maps a connection name to the provider facts explain needs.
// A name may carry an account suffix ("openrouter:dev").
func resolveConnection(ctx context.Context, name string) explain.Connection {
	provider, _, _ := strings.Cut(name, ":")
	tmpl, err := registry.Get(provider)
	if err != nil {
		return resolveCustom(ctx, name)
	}
	c := explain.Connection{
		Known:        true,
		Provider:     tmpl.Provider,
		TypedActions: len(tmpl.Actions) > 0 || len(tmpl.GatewayActions) > 0,
	}
	for _, rt := range tmpl.RuntimeSupport.Supported {
		c.Runtimes = append(c.Runtimes, string(rt))
	}
	if b, ok := tmpl.Binding(); ok {
		c.Binding = explain.BindingOf(explain.BindingTemplate, b)
		c.Hosts = c.Binding.Hosts
		if tmpl.Adapter.Kind == registry.AdapterPostgres {
			c.Adapter = string(tmpl.Adapter.Kind)
		}
		return c
	}
	if hosts := registry.AllowedProviderBaseURLs[tmpl.Provider]; len(hosts) > 0 {
		c.Hosts = append(c.Hosts, hosts...)
	} else if u, err := url.Parse(tmpl.TestStrategy.Endpoint); err == nil && u.Hostname() != "" {
		c.Hosts = []string{u.Hostname()}
	}
	return c
}

// customBinding reads the binding a custom connection declared for itself. It
// is a variable so tests can supply one without a vault.
var customBinding = func(ctx context.Context, name string) (registry.Binding, error) {
	st := newDispatchedStore(loadCLIConfig(nil), llmcontext.DefaultLookup)
	return connections.CustomBindingFor(ctx, st, "", name)
}

// resolveCustom answers for a name that is not a provider: a custom
// connection with the binding it declared. A vault that cannot be read leaves
// the connection unknown rather than guessing.
func resolveCustom(ctx context.Context, name string) explain.Connection {
	if !connections.ValidCustomName(name) {
		return explain.Connection{}
	}
	b, err := customBinding(ctx, name)
	if err != nil {
		return explain.Connection{}
	}
	info := explain.BindingOf(explain.BindingCustom, b)
	return explain.Connection{Known: true, Provider: customProvider, Hosts: info.Hosts, Binding: info}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeRunText(w io.Writer, r explain.Report) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("decision:     %s", r.Decision)
	if r.Tier != nil {
		p("tier:         %s %s (runtime %s)", *r.Tier, *r.TierName, *r.Runtime)
	} else {
		p("tier:         none")
	}
	p("child:        %s (%s)", r.ChildLocation, r.Containment.Verdict)
	if r.Approval.Required {
		p("approval:     required (%s)", r.Approval.Mode)
	} else {
		p("approval:     not needed")
	}
	if len(r.Hosts) > 0 {
		p("hosts:        %s", strings.Join(r.Hosts, ", "))
	}
	if r.Binding != nil {
		p("binding:      %s, %d slot(s)", r.Binding.Source, len(r.Binding.Slots))
	}
	if r.Scope.RuleID != nil {
		p("rule:         %s", *r.Scope.RuleID)
	}
	if r.Scope.TTLSeconds != nil {
		p("ttl:          %ds", *r.Scope.TTLSeconds)
	}
	p("reasons:")
	for _, s := range r.Reasons {
		p("  - %s", s)
	}
	if len(r.Rejected) > 0 {
		p("other tiers:")
		for _, t := range r.Rejected {
			p("  %s %s: %s", t.Tier, t.TierName, t.Why)
			if t.Fix != "" {
				p("      fix: %s", t.Fix)
			}
		}
	}
	p("residual risk: %s", r.ResidualRisk)
	return nil
}

func writePolicyText(w io.Writer, r explain.PolicyReport) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("policy: mode=%s default_deny=%t rules=%d", r.Policy.Mode, r.Policy.DefaultDeny, r.Policy.RuleCount)
	for _, caller := range r.Callers {
		p("")
		p("%s (%s)", caller.Actor, caller.CallerKind)
		for _, cn := range caller.Connections {
			p("  %s", cn.Connection)
			for _, t := range cn.Tiers {
				mark := ""
				if t.Restricted {
					mark = " [restricted by command or directory]"
				}
				p("    %s %-24s %-11s %s%s", t.Tier, t.TierName, t.Status, t.Why, mark)
			}
		}
	}
	for _, n := range r.Notes {
		p("note: %s", n)
	}
	return nil
}
