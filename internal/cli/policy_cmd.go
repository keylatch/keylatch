// Package cli — policy subcommands.
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/spf13/cobra"
)

// newPolicyCmd returns the `keylatch policy` group command.
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage and evaluate the keylatch policy",
	}
	cmd.AddCommand(newPolicyInitCmd())
	cmd.AddCommand(newPolicyAllowCmd())
	cmd.AddCommand(newPolicyListCmd())
	cmd.AddCommand(newPolicyCheckCmd())
	cmd.AddCommand(newPolicyRemoveCmd())
	cmd.AddCommand(newPolicyDenyCmd())
	cmd.AddCommand(newPolicyImportCmd())
	cmd.AddCommand(newPolicyExportCmd())
	return cmd
}

// newPolicyInitCmd creates the default-deny policy: an empty rules file, the
// fallback connection policy that lets only a human use a connection, and
// examples to copy from.
func newPolicyInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default-deny policy and examples",
		Long: `Create the default-deny policy:

  policy.json                 no rules; whatever no rule allows is denied
  policy.d/_default.json      fallback: a human at a terminal may use any
                              connection, every other caller kind is denied
  policy.examples/*.json      examples to edit and import with
                              keylatch policy import <dir>

Replacing an existing policy with --force needs a human at a terminal.`,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			policyPath := paths.Policy(env)
			policyDir := paths.PolicyDir(env)

			_, rulesErr := os.Stat(policyPath)
			_, docsErr := os.Stat(policyDir)
			exists := rulesErr == nil || docsErr == nil
			if exists && !force {
				return fmt.Errorf("a policy already exists at %q; use --force to replace it", policyPath)
			}
			var digest string
			if exists {
				proof, err := requirePolicyChange(c.Context(), presence.ActionPolicyChange, "init", "", "Replace the existing policy with the default-deny policy")
				if err != nil {
					return err
				}
				digest = proof.Digest
			}

			if err := saveDefaultDenyPolicy(policyPath); err != nil {
				return err
			}

			examplesDir, err := installPolicyDocuments(policyPath, policyDir)
			if err != nil {
				return err
			}

			recordPolicyChange(c.Context(), audit.OutcomeOK, "init", "", digest, "")
			fmt.Fprintf(c.OutOrStdout(), "policy initialized at %s\nexamples written to %s\n", policyPath, examplesDir)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing policy (needs a human at a terminal)")
	return cmd
}

// installPolicyDocuments writes the fallback connection policy document and
// the examples beside the rules file, and returns the examples directory.
func installPolicyDocuments(policyPath, policyDir string) (examplesDir string, err error) {
	fallback, err := exampleDocuments("default.json")
	if err != nil {
		return "", err
	}
	if err := (connpolicy.Store{Dir: policyDir}).Replace(fallback); err != nil {
		return "", err
	}
	examplesDir = filepath.Join(filepath.Dir(policyPath), "policy.examples")
	return examplesDir, writeExamples(examplesDir)
}

// saveDefaultDenyPolicy writes an enforcing, default-deny rules file with no rules.
func saveDefaultDenyPolicy(policyPath string) error {
	if err := os.MkdirAll(pathDir(policyPath), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	now := time.Now().UTC()
	return policy.Save(policyPath, policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		Rules:         []policy.Rule{},
		CreatedAt:     now,
		UpdatedAt:     now,
	})
}

// newPolicyAllowCmd appends an allow rule to the policy.
func newPolicyAllowCmd() *cobra.Command {
	var (
		capability string
		command    string
		cwd        string
		ttlStr     string
		approval   bool
		runtime    string
		note       string
	)
	cmd := &cobra.Command{
		Use:   "allow <actor> <connection>",
		Short: "Append an allow rule to the policy",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			actor := args[0]
			connection := args[1]

			proof, err := requirePolicyChange(c.Context(), presence.ActionPolicyChange, "allow", connection,
				"Allow rule: actor %q may use %q (capability %s, runtime %q, command %q, cwd %q, approval %v)",
				actor, connection, capability, runtime, command, cwd, approval)
			if err != nil {
				return err
			}

			policyPath := paths.Policy(llmcontext.DefaultLookup)

			// Ensure policy file exists.
			p, err := loadOrDefaultPolicy(policyPath)
			if err != nil {
				return err
			}

			var ttl int
			if ttlStr != "" {
				d, err := time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
				ttl = int(d.Seconds())
			}

			id, err := newRuleID()
			if err != nil {
				return err
			}

			rule := policy.Rule{
				ID:           id,
				Actor:        actor,
				Connections:  []string{connection},
				Capabilities: []string{capability},
				Approval:     approval,
				Runtime:      runtime,
				Note:         note,
				CreatedAt:    time.Now().UTC(),
			}
			if command != "" {
				rule.Commands = []string{command}
			}
			if cwd != "" {
				rule.CWDs = []string{cwd}
			}
			if ttl > 0 {
				rule.MaxTTLSeconds = ttl
			}

			p.Rules = append(p.Rules, rule)
			if err := policy.Save(policyPath, p); err != nil {
				return err
			}
			recordPolicyChange(c.Context(), audit.OutcomeOK, "allow", connection, proof.Digest, "")
			fmt.Fprintf(c.OutOrStdout(), "rule %s added\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&capability, "capability", "inject", "capability to allow")
	cmd.Flags().StringVar(&command, "command", "", "command glob pattern")
	cmd.Flags().StringVar(&cwd, "cwd", "", "CWD glob pattern")
	cmd.Flags().StringVar(&ttlStr, "ttl", "", "maximum TTL (e.g. 1h)")
	cmd.Flags().BoolVar(&approval, "approval", false, "require approval token")
	cmd.Flags().StringVar(&runtime, "runtime", "", "runtime mode filter")
	cmd.Flags().StringVar(&note, "note", "", "free-text note")
	return cmd
}

// newPolicyListCmd lists rules value-free.
func newPolicyListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policy rules (value-free)",
		RunE: func(c *cobra.Command, _ []string) error {
			policyPath := paths.Policy(llmcontext.DefaultLookup)
			p, err := loadOrDefaultPolicy(policyPath)
			if err != nil {
				return err
			}

			if jsonOut {
				// Deterministic JSON — no timestamps.
				type jsonRule struct {
					ID           string   `json:"id"`
					Actor        string   `json:"actor"`
					Connections  []string `json:"connections"`
					Capabilities []string `json:"capabilities"`
					Commands     []string `json:"commands,omitempty"`
					CWDs         []string `json:"cwds,omitempty"`
					Runtime      string   `json:"runtime,omitempty"`
					Approval     bool     `json:"approval,omitempty"`
					Note         string   `json:"note,omitempty"`
				}
				out := make([]jsonRule, 0, len(p.Rules))
				for _, r := range p.Rules {
					out = append(out, jsonRule{
						ID:           r.ID,
						Actor:        r.Actor,
						Connections:  r.Connections,
						Capabilities: r.Capabilities,
						Commands:     r.Commands,
						CWDs:         r.CWDs,
						Runtime:      r.Runtime,
						Approval:     r.Approval,
						Note:         r.Note,
					})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			// Table format.
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tACTOR\tCONNECTIONS\tCAPABILITIES\tRUNTIME\tNOTE")
			for _, r := range p.Rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Actor,
					strings.Join(r.Connections, ","),
					strings.Join(r.Capabilities, ","),
					r.Runtime, r.Note,
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

// newPolicyCheckCmd dry-runs a policy decision.
func newPolicyCheckCmd() *cobra.Command {
	var (
		capability string
		jsonOut    bool
		as         string
		rtFlag     string
		action     string
		checkActor string
	)
	cmd := &cobra.Command{
		Use:   "check <connection> --as agent|host|service|human [--runtime <r>] [--action <a>] [-- <cmd...>]\n  check <actor> <connection> [-- <cmd...>]",
		Short: "Dry-run a policy decision (read-only; safe in LLM sessions)",
		Long: `Dry-run the decision keylatch would make, with the same code run, call and the
gateway use. Nothing is changed and no presence is needed.

With --as, the first form asks what a caller of that kind may do with the
connection. The second form evaluates the rules file for an actor.`,
		Args: func(c *cobra.Command, args []string) error {
			if c.Flags().Changed("as") {
				if len(args) < 1 || (c.ArgsLenAtDash() >= 0 && c.ArgsLenAtDash() != 1) || (c.ArgsLenAtDash() < 0 && len(args) != 1) {
					return fmt.Errorf("check --as takes one connection, optionally followed by -- <cmd...>")
				}
				return nil
			}
			return cobra.MinimumNArgs(2)(c, args)
		},
		RunE: func(c *cobra.Command, args []string) error {
			if c.Flags().Changed("as") {
				return runPolicyCheckAs(c, args, policyCheckOptions{as: as, runtime: rtFlag, action: action, actor: checkActor, json: jsonOut})
			}
			actor := args[0]
			connection := args[1]

			var command []string
			if c.ArgsLenAtDash() >= 0 {
				command = args[c.ArgsLenAtDash():]
			}

			policyPath := paths.Policy(llmcontext.DefaultLookup)
			p, err := loadOrDefaultPolicy(policyPath)
			if err != nil {
				return err
			}

			req := policy.Request{
				Actor:      actor,
				Connection: connection,
				Capability: capability,
				Command:    command,
				LLMSession: llmcontext.IsLLMSession(llmcontext.DefaultLookup),
			}

			// policy.check may panic for permissive+LLM; guard it.
			var d policy.Decision
			func() {
				defer func() {
					if r := recover(); r != nil {
						d = policy.Decision{
							Allow:   false,
							Reason:  fmt.Sprintf("invariant violation: %v", r),
							SafeFix: "use ModeEnforcing in LLM sessions",
						}
					}
				}()
				d = p.Check(req)
			}()

			if jsonOut {
				type jsonDecision struct {
					Allow            bool   `json:"allow"`
					Reason           string `json:"reason,omitempty"`
					SafeFix          string `json:"safe_fix,omitempty"`
					ApprovalRequired bool   `json:"approval_required,omitempty"`
					MatchedRuleID    string `json:"matched_rule_id,omitempty"`
				}
				out := jsonDecision{
					Allow:            d.Allow,
					Reason:           d.Reason,
					SafeFix:          d.SafeFix,
					ApprovalRequired: d.ApprovalRequired,
				}
				if d.MatchedRule != nil {
					out.MatchedRuleID = d.MatchedRule.ID
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			if d.Allow {
				fmt.Fprintf(c.OutOrStdout(), "ALLOW")
				if d.MatchedRule != nil {
					fmt.Fprintf(c.OutOrStdout(), " (rule: %s)", d.MatchedRule.ID)
				}
				if d.ApprovalRequired {
					fmt.Fprintf(c.OutOrStdout(), " [approval required]")
				}
				fmt.Fprintln(c.OutOrStdout())
			} else {
				fmt.Fprintf(c.OutOrStdout(), "DENY")
				if d.Reason != "" {
					fmt.Fprintf(c.OutOrStdout(), ": %s", d.Reason)
				}
				if d.SafeFix != "" {
					fmt.Fprintf(c.OutOrStdout(), "\n  fix: %s", d.SafeFix)
				}
				fmt.Fprintln(c.OutOrStdout())
				os.Exit(exitcode.SecurityBlock)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&capability, "capability", "inject", "capability to check (rules form)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	cmd.Flags().StringVar(&as, "as", "", "caller kind to check as: agent, host, service or human")
	cmd.Flags().StringVar(&rtFlag, "runtime", "", "runtime mode of the request (with --as)")
	cmd.Flags().StringVar(&action, "action", enforce.DefaultAction, "capability asked for (with --as)")
	cmd.Flags().StringVar(&checkActor, "actor", "", "rules-file actor to check as (with --as; default inferred)")
	return cmd
}

// newPolicyRemoveCmd removes a rule by ID.
func newPolicyRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <rule-id>",
		Short: "Remove a policy rule by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ruleID := args[0]
			policyPath := paths.Policy(llmcontext.DefaultLookup)

			proof, err := requirePolicyChange(c.Context(), presence.ActionPolicyChange, "remove", "", "Remove policy rule %s", ruleID)
			if err != nil {
				return err
			}

			p, err := loadOrDefaultPolicy(policyPath)
			if err != nil {
				return err
			}

			original := len(p.Rules)
			filtered := p.Rules[:0]
			for _, r := range p.Rules {
				if r.ID != ruleID {
					filtered = append(filtered, r)
				}
			}
			if len(filtered) == original {
				return fmt.Errorf("rule %q not found", ruleID)
			}
			p.Rules = filtered

			if err := policy.Save(policyPath, p); err != nil {
				return err
			}
			recordPolicyChange(c.Context(), audit.OutcomeOK, "remove", "", proof.Digest, "")
			fmt.Fprintf(c.OutOrStdout(), "rule %s removed\n", ruleID)
			return nil
		},
	}
}

// loadOrDefaultPolicy loads the policy from path, returning a safe default
// if the file doesn't exist.
func loadOrDefaultPolicy(policyPath string) (policy.Policy, error) {
	p, err := policy.Load(policyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return policy.Policy{
				SchemaVersion: 1,
				Mode:          policy.ModeEnforcing,
				DefaultDeny:   true,
				Rules:         []policy.Rule{},
				CreatedAt:     time.Now().UTC(),
				UpdatedAt:     time.Now().UTC(),
			}, nil
		}
		return policy.Policy{}, err
	}
	return p, nil
}

// newRuleID generates a UUID v4-like identifier for a new rule.
func newRuleID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate rule ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

// pathDir returns the directory component of a path (avoids importing filepath
// for a simple operation).
func pathDir(p string) string {
	idx := strings.LastIndexByte(p, '/')
	if idx < 0 {
		return "."
	}
	return p[:idx]
}
