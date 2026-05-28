// Package cli — Phase 9 gateway rules subcommands (stub).
//
// Rules persist to ~/.keylatch/gateway-rules.json (mode 0o600).
package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// GatewayRule is a single gateway rule entry.
type GatewayRule struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Action    string    `json:"action"`
	Kind      string    `json:"kind"`                 // "block"|"require-approval"|"rate-limit"
	RateLimit string    `json:"rate_limit,omitempty"` // e.g. "10/1m"
	CreatedAt time.Time `json:"created_at"`
}

// newRulesCmd returns the `keylatch rules` group command.
func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage gateway rules (Phase 9 stub)",
	}
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesCreateCmd())
	cmd.AddCommand(newRulesDeleteCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List gateway rules",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			rules, err := loadGatewayRules(env)
			if err != nil {
				return err
			}
			if useJSON {
				b, _ := json.Marshal(rules)
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tPROVIDER\tACTION\tKIND\tCREATED")
			for _, r := range rules {
				id := r.ID
				if len(id) > 12 {
					id = id[:12] + "..."
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					id,
					r.Provider,
					r.Action,
					r.Kind,
					r.CreatedAt.Format(time.RFC3339),
				)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}

func newRulesCreateCmd() *cobra.Command {
	var (
		provider        string
		action          string
		block           bool
		requireApproval bool
		rateLimit       string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a gateway rule",
		RunE: func(c *cobra.Command, _ []string) error {
			if provider == "" || action == "" {
				return fmt.Errorf("rules create: --provider and --action are required")
			}

			kind := ""
			switch {
			case block:
				kind = "block"
			case requireApproval:
				kind = "require-approval"
			case rateLimit != "":
				kind = "rate-limit"
			default:
				return fmt.Errorf("rules create: one of --block, --require-approval, or --rate-limit is required")
			}

			env := llmcontext.DefaultLookup
			rules, err := loadGatewayRules(env)
			if err != nil {
				return err
			}

			id, err := newGatewayRuleID()
			if err != nil {
				return fmt.Errorf("rules create: generate id: %w", err)
			}

			rule := GatewayRule{
				ID:        id,
				Provider:  provider,
				Action:    action,
				Kind:      kind,
				RateLimit: rateLimit,
				CreatedAt: time.Now().UTC(),
			}
			rules = append(rules, rule)

			if err := saveGatewayRules(env, rules); err != nil {
				return fmt.Errorf("rules create: save: %w", err)
			}

			fmt.Fprintf(c.OutOrStdout(), "rule created: %s (%s %s.%s)\n", rule.ID, kind, provider, action)
			return nil
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "provider slug")
	cmd.Flags().StringVar(&action, "action", "", "action name")
	cmd.Flags().BoolVar(&block, "block", false, "block this action")
	cmd.Flags().BoolVar(&requireApproval, "require-approval", false, "require approval for this action")
	cmd.Flags().StringVar(&rateLimit, "rate-limit", "", "rate limit (e.g. 10/1m)")
	return cmd
}

func newRulesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <rule-id>",
		Short: "Delete a gateway rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			ruleID := args[0]

			rules, err := loadGatewayRules(env)
			if err != nil {
				return err
			}

			var updated []GatewayRule
			found := false
			for _, r := range rules {
				if r.ID == ruleID {
					found = true
					continue
				}
				updated = append(updated, r)
			}
			if !found {
				return fmt.Errorf("rules delete: rule %q not found", ruleID)
			}

			if err := saveGatewayRules(env, updated); err != nil {
				return fmt.Errorf("rules delete: save: %w", err)
			}

			fmt.Fprintf(c.OutOrStdout(), "rule deleted: %s\n", ruleID)
			return nil
		},
	}
}

// --- helpers ---

func loadGatewayRules(env func(string) string) ([]GatewayRule, error) {
	path := paths.GatewayRules(env)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rules: read %q: %w", path, err)
	}
	var rules []GatewayRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("rules: parse: %w", err)
	}
	return rules, nil
}

func saveGatewayRules(env func(string) string, rules []GatewayRule) error {
	path := paths.GatewayRules(env)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("rules: mkdir: %w", err)
	}
	data, _ := json.MarshalIndent(rules, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("rules: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rules: rename: %w", err)
	}
	return nil
}

func newGatewayRuleID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("rule_%x", b), nil
}

// randRead is an alias for use in gateway_cmd.go.
//
//nolint:unused // planned: used by gateway token generation in Phase 9 auth refactor
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}
