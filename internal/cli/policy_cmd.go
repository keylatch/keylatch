// Package cli — policy subcommands.
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
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
	return cmd
}

// newPolicyInitCmd creates ~/.keylatch/policy.json with safe defaults.
func newPolicyInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default policy file",
		RunE: func(c *cobra.Command, _ []string) error {
			policyPath := paths.Policy(llmcontext.DefaultLookup)

			if !force {
				if _, err := os.Stat(policyPath); err == nil {
					return fmt.Errorf("policy file already exists at %q; use --force to overwrite", policyPath)
				}
			}

			if err := os.MkdirAll(pathDir(policyPath), 0o700); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}

			now := time.Now().UTC()
			p := policy.Policy{
				SchemaVersion: 1,
				Mode:          policy.ModeEnforcing,
				DefaultDeny:   true,
				Rules:         []policy.Rule{},
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			if err := policy.Save(policyPath, p); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "policy initialized at %s\n", policyPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing policy file")
	return cmd
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

			// Refuse --runtime direct_classic_sandboxed inside LLM session.
			if runtime == "direct_classic_sandboxed" && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "error: --runtime direct_classic_sandboxed is not permitted inside an LLM session")
				os.Exit(exitcode.SecurityBlock)
				return nil
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
	)
	cmd := &cobra.Command{
		Use:   "check <actor> <connection> [-- <cmd...>]",
		Short: "Dry-run a policy decision (safe in LLM sessions)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
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
	cmd.Flags().StringVar(&capability, "capability", "inject", "capability to check")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
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

			p, err := policy.Load(policyPath)
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
		if os.IsNotExist(err) {
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
