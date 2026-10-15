package cli

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

// parseLocalOnlyFlags reads --class and --local-only from connect.
func parseLocalOnlyFlags(c *cobra.Command) (localonly.Class, map[string]localonly.Mode, error) {
	classFlag, _ := c.Flags().GetString("class")
	class, err := localonly.ParseClass(classFlag)
	if err != nil {
		return "", nil, err
	}
	specs, _ := c.Flags().GetStringArray("local-only")
	modes := map[string]localonly.Mode{}
	for _, spec := range specs {
		name, modeName, ok := strings.Cut(spec, "=")
		if !ok {
			return "", nil, fmt.Errorf("invalid --local-only %q; expected FIELD=MODE", spec)
		}
		mode, err := localonly.ParseMode(modeName)
		if err != nil {
			return "", nil, err
		}
		if err := localonly.CheckConnection(class, mode); err != nil {
			return "", nil, fmt.Errorf("--local-only %s: %w", name, err)
		}
		modes[name] = mode
	}
	return class, modes, nil
}

// suggestLocalOnly offers ephemeral for fields that look like in-process
// secrets on dev/test connections. The suggestion is applied only when confirm
// is non-nil and returns true; agent callers and non-interactive runs pass nil
// and get a hint.
func suggestLocalOnly(c *cobra.Command, tmpl registry.ConnectionTemplate, class localonly.Class, modes map[string]localonly.Mode, confirm func(field string) bool) {
	for _, sf := range tmpl.SecretFields {
		if _, set := modes[sf.Name]; set {
			continue
		}
		if _, ok := localonly.Suggest(class, sf.Name, sf.EnvVar); !ok {
			continue
		}
		if confirm != nil {
			if confirm(sf.Name) {
				modes[sf.Name] = localonly.Ephemeral
			}
			continue
		}
		fmt.Fprintf(c.ErrOrStderr(), "hint: %s could use --local-only %s=ephemeral\n", sf.Name, sf.Name)
	}
}

func confirmEphemeral(c *cobra.Command) func(string) bool {
	return func(field string) bool {
		fmt.Fprintf(c.ErrOrStderr(), "%s looks like a secret only the app itself uses. Generate a random value per run instead of storing one? [y/N] ", field)
		a := strings.ToLower(strings.TrimSpace(readLine()))
		return a == "y" || a == "yes"
	}
}

func formatLocalOnly(modes map[string]localonly.Mode) string {
	if len(modes) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(modes))
	for _, sf := range slices.Sorted(maps.Keys(modes)) {
		parts = append(parts, sf+"="+string(modes[sf]))
	}
	return strings.Join(parts, ",")
}

// newLocalOnlyCmd returns `local-only set`, which changes how one field of an
// existing connection is delivered.
func newLocalOnlyCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "local-only",
		Short: "Manage local-only delivery of connection fields",
	}
	set := &cobra.Command{
		Use:   "set <provider> <field> <ephemeral|operation|contained|none>",
		Short: "Change a field's local-only mode (weakening is human-only)",
		Args:  cobra.ExactArgs(3),
		RunE: func(c *cobra.Command, args []string) error {
			var mode localonly.Mode
			if args[2] != "none" {
				m, err := localonly.ParseMode(args[2])
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.UserError)
					return nil
				}
				mode = m
			}
			namespace, _ := c.Flags().GetString("namespace")
			human := !llmcontext.IsLLMSession(llmcontext.DefaultLookup)
			store := newDispatchedStore(loadCLIConfig(c), llmcontext.DefaultLookup)
			if err := connections.SetLocalOnly(c.Context(), namespace, args[0], args[1], mode, human, store); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				code := exitcode.OperationFailed
				switch {
				case errors.Is(err, connections.ErrHumanOnly):
					code = exitcode.SecurityBlock
				case errors.Is(err, localonly.ErrEphemeralClass), errors.Is(err, localonly.ErrInvalidMode):
					code = exitcode.UserError
				}
				os.Exit(code)
				return nil
			}
			fmt.Fprintf(c.OutOrStdout(), "%s.%s local-only: %s\n", args[0], args[1], args[2])
			return nil
		},
	}
	set.Flags().String("namespace", "default", "vault namespace")
	root.AddCommand(set)
	return root
}
