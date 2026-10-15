package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/examples"
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/spf13/cobra"
)

// exampleDocuments parses the embedded example documents with the given file
// names, or all of them when none are given.
func exampleDocuments(names ...string) (map[string]connpolicy.Document, error) {
	entries, err := examples.PolicyD.ReadDir("policy.d")
	if err != nil {
		return nil, err
	}
	out := map[string]connpolicy.Document{}
	for _, e := range entries {
		if len(names) > 0 && !slices.Contains(names, e.Name()) {
			continue
		}
		data, err := examples.PolicyD.ReadFile("policy.d/" + e.Name())
		if err != nil {
			return nil, err
		}
		d, err := connpolicy.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("example %s: %w", e.Name(), err)
		}
		out[d.Connection] = d
	}
	return out, nil
}

// writeExamples copies the embedded example documents into dir under their
// own file names.
func writeExamples(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := examples.PolicyD.ReadDir("policy.d")
	if err != nil {
		return err
	}
	for _, e := range entries {
		data, err := examples.PolicyD.ReadFile("policy.d/" + e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type policyCheckOptions struct {
	as, runtime, action, actor string
	json                       bool
}

type policyCheckResult struct {
	Connection       string `json:"connection"`
	Caller           string `json:"caller"`
	Runtime          string `json:"runtime,omitempty"`
	Action           string `json:"action"`
	Allow            bool   `json:"allow"`
	Reason           string `json:"reason,omitempty"`
	SafeFix          string `json:"safe_fix,omitempty"`
	Source           string `json:"source"`
	RuleID           string `json:"rule_id,omitempty"`
	GrantID          string `json:"grant_id,omitempty"`
	ApprovalRequired bool   `json:"approval_required,omitempty"`
	MaxTTLSeconds    int    `json:"max_ttl_seconds,omitempty"`
}

// parseCallerKind accepts the four kinds a policy can name.
func parseCallerKind(s string) (callerkind.Kind, error) {
	k := callerkind.Kind(s)
	if !slices.Contains(connpolicy.Kinds, k) {
		return "", NewUsageError("--as %q is not a caller kind; use agent, host, service or human", s)
	}
	return k, nil
}

// runPolicyCheckAs answers what enforce.Decide would answer for a caller of
// the given kind. It reads policy and changes nothing.
func runPolicyCheckAs(c *cobra.Command, args []string, o policyCheckOptions) error {
	kind, err := parseCallerKind(o.as)
	if err != nil {
		return err
	}
	if o.runtime != "" {
		if err := policy.ValidateRuntimeMode(o.runtime); err != nil {
			return NewUsageError("--runtime: %v", err)
		}
	}
	var command []string
	if dash := c.ArgsLenAtDash(); dash >= 0 {
		command = args[dash:]
	}
	d := enforce.Decide(c.Context(), enforce.Request{
		Connection: args[0],
		Action:     o.action,
		Runtime:    o.runtime,
		Caller:     kind,
		Actor:      o.actor,
		Command:    command,
	})
	res := policyCheckResult{
		Connection: args[0], Caller: string(kind), Runtime: o.runtime, Action: o.action,
		Allow: d.Allow, Reason: d.Reason, SafeFix: d.SafeFix, Source: d.Source, RuleID: d.RuleID, GrantID: d.GrantID,
		ApprovalRequired: d.ApprovalRequired, MaxTTLSeconds: int(d.MaxTTL.Seconds()),
	}
	if o.json {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(c.OutOrStdout(), string(b))
	} else if d.Allow {
		fmt.Fprintf(c.OutOrStdout(), "ALLOW (%s)", d.Source)
		if d.ApprovalRequired {
			fmt.Fprint(c.OutOrStdout(), " [approval required]")
		}
		fmt.Fprintln(c.OutOrStdout())
	} else {
		fmt.Fprintf(c.OutOrStdout(), "DENY: %s\n", d.Reason)
		if d.SafeFix != "" {
			fmt.Fprintf(c.OutOrStdout(), "  fix: %s\n", d.SafeFix)
		}
	}
	if !d.Allow {
		return NewPolicyDeny("policy check: %s", d.Reason)
	}
	return nil
}

func newPolicyImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <dir>",
		Short: "Replace the connection policy with the documents in a directory",
		Long: `Validate every *.json file in <dir> against the connection policy schema,
show what would change, and replace the connection policy with them. Nothing
changes if any file is invalid. The replacement needs a human at a terminal:
the summary shown there is the diff.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir := args[0]
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				return NewUsageError("policy import: %q is not a directory", dir)
			}
			incoming, err := connpolicy.ReadDir(dir, false)
			if err != nil {
				return NewUsageError("policy import: %v; nothing was changed", err)
			}
			if len(incoming) == 0 {
				return NewUsageError("policy import: no *.json files in %q", dir)
			}

			store := connpolicy.Store{Dir: paths.PolicyDir(llmcontext.DefaultLookup)}
			current, err := store.LoadAll()
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "policy import: the existing policy is unreadable and will be replaced: %v\n", err)
				current = map[string]connpolicy.Document{}
			}
			lines := connpolicy.Diff(current, incoming)
			if len(lines) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "policy import: no changes")
				return nil
			}
			diff := "  " + strings.Join(lines, "\n  ")
			fmt.Fprintf(c.OutOrStdout(), "Changes:\n%s\n", diff)

			proof, err := requirePolicyChange(c.Context(), presence.ActionPolicyChange, "import", "",
				"Import %d connection policy document(s) from %s:\n%s", len(incoming), dir, diff)
			if err != nil {
				return err
			}
			if err := store.Replace(incoming); err != nil {
				return fmt.Errorf("policy import: %w", err)
			}
			recordPolicyChange(c.Context(), audit.OutcomeOK, "import", "", proof.Digest, "")
			fmt.Fprintf(c.OutOrStdout(), "policy import: %d document(s) imported\n", len(incoming))
			return nil
		},
	}
}

func newPolicyExportCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "export <dir>",
		Short: "Write the connection policy documents to a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir := args[0]
			docs, err := (connpolicy.Store{Dir: paths.PolicyDir(llmcontext.DefaultLookup)}).LoadAll()
			if err != nil {
				return fmt.Errorf("policy export: %w", err)
			}
			if len(docs) == 0 {
				return NewUsageError("policy export: there is no connection policy; run `keylatch policy init`")
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("policy export: %w", err)
			}
			for _, conn := range connpolicy.Connections(docs) {
				path := filepath.Join(dir, connpolicy.FileName(conn))
				if _, err := os.Stat(path); err == nil && !force {
					return NewUsageError("policy export: %s exists; use --force to overwrite", path)
				} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("policy export: %w", err)
				}
				b, err := connpolicy.Marshal(docs[conn])
				if err != nil {
					return err
				}
				if err := os.WriteFile(path, b, 0o600); err != nil {
					return fmt.Errorf("policy export: %w", err)
				}
			}
			fmt.Fprintf(c.OutOrStdout(), "policy export: %d document(s) written to %s\n", len(docs), dir)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite files that exist")
	return cmd
}

func newPolicyDenyCmd() *cobra.Command {
	var as string
	cmd := &cobra.Command{
		Use:   "deny <connection> --as agent|host|service|human",
		Short: "Deny a caller kind the use of a connection",
		Long: `Set callers.<kind> of the connection's policy document to deny, creating the
document if the connection has none. Needs a human at a terminal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			kind, err := parseCallerKind(as)
			if err != nil {
				return err
			}
			conn := args[0]
			proof, err := requirePolicyChange(c.Context(), presence.ActionPolicyChange, "deny", conn, "Deny %s callers the use of %q", kind, conn)
			if err != nil {
				return err
			}
			store := connpolicy.Store{Dir: paths.PolicyDir(llmcontext.DefaultLookup)}
			docs, err := store.LoadAll()
			if err != nil {
				return fmt.Errorf("policy deny: %w", err)
			}
			doc, ok := docs[conn]
			if !ok {
				doc = connpolicy.Document{SchemaVersion: connpolicy.SchemaVersion, Connection: conn, Default: "deny"}
			}
			if doc.Callers == nil {
				doc.Callers = map[callerkind.Kind]connpolicy.CallerRule{}
			}
			doc.Callers[kind] = connpolicy.CallerRule{}
			if err := doc.Validate(); err != nil {
				return NewUsageError("policy deny: %v", err)
			}
			docs[conn] = doc
			if err := store.Replace(docs); err != nil {
				return fmt.Errorf("policy deny: %w", err)
			}
			recordPolicyChange(c.Context(), audit.OutcomeOK, "deny", conn, proof.Digest, "")
			fmt.Fprintf(c.OutOrStdout(), "%s callers are denied the use of %s\n", kind, conn)
			return nil
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "caller kind to deny: agent, host, service or human (required)")
	_ = cmd.MarkFlagRequired("as")
	return cmd
}
