package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	klruntime "github.com/keylatch/keylatch/internal/runtime"
	"github.com/spf13/cobra"
)

// newConfigCmd returns the `config` subcommand with get/set/list subcommands.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage keylatch non-secret configuration",
		Long: `Manage the keylatch configuration file (~/.keylatch/config.json).

Only non-secret values are stored here. Use 'keylatch set' to store credentials.`,
	}
	cmd.AddCommand(newConfigGetCmd())
	cmd.AddCommand(newConfigSetCmd())
	cmd.AddCommand(newConfigListCmd())
	return cmd
}

// newConfigGetCmd returns `config get <key>`.
func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			key := args[0]
			cfgPath := paths.Config(llmcontext.DefaultLookup)
			cfg, err := loadOrDefault(cfgPath)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config get: %v\n", err)
				os.Exit(1)
			}

			val, found := getField(cfg, key)
			if !found {
				fmt.Fprintf(c.ErrOrStderr(), "config get: unknown key %q\n", key)
				os.Exit(1)
			}
			fmt.Fprintln(c.OutOrStdout(), val)
			return nil
		},
	}
}

// newConfigSetCmd returns `config set <key> <value>`.
func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: `Set a non-secret configuration value. Keys that look like credentials
(password, secret, token, key, etc.) are rejected — use 'keylatch set' instead.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			// S05-4: blocklist check.
			if err := config.ValidateSetKey(key); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config set: %v\n", err)
				os.Exit(1)
			}

			cfgPath := paths.Config(llmcontext.DefaultLookup)
			cfg, err := loadOrDefault(cfgPath)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config set: %v\n", err)
				os.Exit(1)
			}

			// EPIC-17: validate operating mode before persisting.
			if strings.ToLower(key) == "mode" {
				if _, parseErr := klruntime.ParseMode(value); parseErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "config set: %v\n", parseErr)
					os.Exit(1)
				}
			}

			if err := setField(&cfg, key, value); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config set: %v\n", err)
				os.Exit(1)
			}

			if err := config.Save(cfgPath, cfg); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config set: %v\n", err)
				os.Exit(1)
			}

			fmt.Fprintf(c.OutOrStdout(), "set %s=%s\n", key, value)
			return nil
		},
	}
}

// newConfigListCmd returns `config list`.
func newConfigListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all configuration values",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			cfgPath := paths.Config(llmcontext.DefaultLookup)
			cfg, err := loadOrDefault(cfgPath)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "config list: %v\n", err)
				os.Exit(1)
			}

			if jsonOut {
				b, marshalErr := json.MarshalIndent(cfg, "", "  ")
				if marshalErr != nil {
					fmt.Fprintf(c.ErrOrStderr(), "config list: %v\n", marshalErr)
					os.Exit(1)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
			} else {
				printConfig(c, cfg)
			}
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "output as JSON")
	return cmd
}

func loadOrDefault(cfgPath string) (config.Config, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if os.IsNotExist(unwrapErr(err)) {
			return config.Default(), nil
		}
		// For other errors (e.g. parse failure), return default with a warning.
		return config.Default(), nil
	}
	return cfg, nil
}

func unwrapErr(err error) error {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
		} else {
			return err
		}
	}
	return nil
}

// getField retrieves a top-level Config field by its JSON tag name.
func getField(cfg config.Config, key string) (string, bool) {
	v := reflect.ValueOf(cfg)
	t := v.Type()
	key = strings.ToLower(key)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		tagName := strings.Split(tag, ",")[0]
		if strings.ToLower(tagName) == key {
			return fmt.Sprintf("%v", v.Field(i).Interface()), true
		}
	}
	return "", false
}

// setField updates a top-level Config field by its JSON tag name.
func setField(cfg *config.Config, key, value string) error {
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	key = strings.ToLower(key)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		tagName := strings.Split(tag, ",")[0]
		if strings.ToLower(tagName) == key {
			field := v.Field(i)
			if !field.CanSet() {
				return fmt.Errorf("field %q is read-only", key)
			}
			switch field.Kind() {
			case reflect.String:
				field.SetString(value)
			case reflect.Int, reflect.Int64:
				// Not supported via config set for now.
				return fmt.Errorf("numeric field %q cannot be set via config set; edit config.json directly", key)
			default:
				return fmt.Errorf("field %q type not supported via config set", key)
			}
			return nil
		}
	}
	return fmt.Errorf("unknown config key %q", key)
}

func printConfig(c *cobra.Command, cfg config.Config) {
	w := c.OutOrStdout()
	v := reflect.ValueOf(cfg)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		tagName := strings.Split(tag, ",")[0]
		if tagName == "" || tagName == "-" {
			continue
		}
		fmt.Fprintf(w, "%s = %v\n", tagName, v.Field(i).Interface())
	}
}
