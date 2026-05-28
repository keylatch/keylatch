package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/cmderr"
	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/spf13/cobra"
)

// newPhase3CallCmd returns the `call` subcommand.
//
// `keylatch call <connection> <action>` dispatches a single named HTTP action
// from the provider's action catalog. The credential is read from the vault,
// used as a Bearer token, and zeroed after use. The response body is passed
// through the redactor before printing — credential-shaped bytes are replaced
// with [REDACTED:<pattern>].
//
// No raw credential bytes appear in stdout, stderr, or audit logs.
func newPhase3CallCmd() *cobra.Command {
	var (
		rawParams       []string
		runtimeOverride string
		listActions     bool
		useJSON         bool
		includeHeaders  bool
		namespace       string
		account         string
		noDaemonStart   bool
	)

	cmd := &cobra.Command{
		Use:   "call <connection> <action>",
		Short: "Call a provider action via the credential vault",
		Long: `call dispatches a single named HTTP action from a provider's action catalog.

The connection credential is read from the vault and used as a Bearer token.
Response bodies are redacted before printing — credential-shaped bytes are
replaced with [REDACTED:<pattern>].

Use --list to show available actions for a connection.

Examples:
  keylatch call openai list-models
  keylatch call openai list-files --param purpose=fine-tune
  keylatch call openai list-models --json
  keylatch call openai --list`,
		Args: func(cmd *cobra.Command, args []string) error {
			list, _ := cmd.Flags().GetBool("list")
			if list {
				if len(args) < 1 {
					return fmt.Errorf("requires a connection name")
				}
				return nil
			}
			if len(args) != 2 {
				return fmt.Errorf("requires exactly 2 arguments: <connection> <action>")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			if namespace == "" {
				namespace = "default"
			}

			connectionName := args[0]

			// --list: show available actions for this connection and exit.
			if listActions {
				return runCallList(c, connectionName, useJSON)
			}

			actionName := args[1]

			// Auto-spawn keylatchd if it is not already running (Epic 31).
			if !noDaemonStart && !daemon.IsRunning() {
				fmt.Fprintln(c.ErrOrStderr(), "Starting Keylatch daemon... (will run in background)")
				if err := daemon.Spawn(); err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "keylatch: %v\n", err)
					os.Exit(exitcode.OperationFailed)
				}
			}

			// Look up the provider template from the registry.
			tmpl, err := registry.Get(connectionName)
			if err != nil {
				cerr := cmderr.Wrap(
					fmt.Sprintf("provider %q not found in registry", connectionName),
					err,
					"run 'keylatch registry list' to see available providers",
					"KL-3002",
				)
				cmderr.Format(c.ErrOrStderr(), cerr)
				os.Exit(exitcode.UserError)
			}

			// Verify the action exists in the template's catalog.
			if len(tmpl.Actions) == 0 {
				printStructuredError(c, useJSON, "action_not_found",
					fmt.Sprintf("provider %q has no actions defined in its template", connectionName),
					"add an 'actions:' block to the provider template to enable keylatch call",
				)
				os.Exit(exitcode.UserError)
			}
			if _, ok := tmpl.Actions[actionName]; !ok {
				var available []string
				for name := range tmpl.Actions {
					available = append(available, name)
				}
				printStructuredError(c, useJSON, "action_not_found",
					fmt.Sprintf("action %q is not defined for provider %q", actionName, connectionName),
					fmt.Sprintf("available actions: %s", strings.Join(available, ", ")),
				)
				os.Exit(exitcode.UserError)
			}

			// Resolve base URL from the provider's test_strategy endpoint.
			// The test_strategy.endpoint contains the full first-party URL (e.g.
			// "https://api.openai.com/v1/models"). We extract just the scheme+host.
			baseURL, err := baseURLFromTemplate(tmpl)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: could not determine base URL for provider %q: %v\n", connectionName, err)
				os.Exit(exitcode.OperationFailed)
			}

			// Override runtime if requested.
			if runtimeOverride != "" {
				slog.Debug("runtime override applied", "mode", runtimeOverride)
			}

			// Parse --param flags into a map.
			params, err := parseParamFlags(rawParams)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: invalid --param flag: %v\n", err)
				os.Exit(exitcode.UserError)
			}

			// Read the credential from the vault. This is the value-bearing path.
			// The credential is used only as a Bearer token and is zeroed after use.
			category := tmpl.Category
			if category == "" {
				category = "ai"
			}
			var cred []byte
			if len(tmpl.SecretFields) > 0 {
				sf := tmpl.SecretFields[0]
				fieldPath := fmt.Sprintf("%s/%s/%s/%s", namespace, category, connectionName, sf.Name)
				credBytes, _, readErr := store.Get(ctx, fieldPath)
				if readErr != nil {
					cerr := cmderr.Wrap(
						fmt.Sprintf("no stored credential for connection %q", connectionName),
						readErr,
						fmt.Sprintf("run 'keylatch connect %s' to set up the connection", connectionName),
						"KL-3003",
					)
					cmderr.Format(c.ErrOrStderr(), cerr)
					os.Exit(exitcode.Missing)
				}
				cred = credBytes
			}

			// Dispatch the action.
			result, execErr := runner.ExecuteAction(ctx, baseURL, connectionName, actionName, params, string(cred))
			// Zero the credential bytes immediately after use — never keep them alive.
			zeroBytes(cred)

			if execErr != nil {
				printStructuredError(c, useJSON, "dispatch_failed",
					fmt.Sprintf("action dispatch failed: %v", execErr),
					"check your network connection and that the gateway is running",
				)
				os.Exit(exitcode.OperationFailed)
			}

			// Redact credential-shaped bytes from the response body.
			redacted := runner.Redact(result.Body)

			// Emit output.
			if useJSON {
				printCallResultJSON(c, result.StatusCode, result.DurationMs, redacted, result.Headers, includeHeaders)
			} else {
				fmt.Fprintf(c.OutOrStdout(), "%s\n", redacted)
			}

			// Non-2xx: exit 1.
			if result.StatusCode < 200 || result.StatusCode >= 300 {
				os.Exit(exitcode.UserError)
			}

			// Push receipt to keylatchd dashboard (best-effort).
			receipt := runner.RuntimeReceipt{
				Provider:        connectionName,
				Capability:      actionName,
				Runtime:         string(tmpl.RuntimeSupport.Preferred),
				PolicyDecision:  "approved",
				CredentialShape: "provider_root",
				TTL:             time.Hour,
			}
			pushReceiptToUI(ctx, receipt)

			_ = account // reserved for multi-account future use
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&rawParams, "param", nil, "action parameter as key=value (repeat for multiple)")
	cmd.Flags().StringVar(&runtimeOverride, "runtime", "", "override runtime mode")
	cmd.Flags().BoolVar(&listActions, "list", false, "list available actions for the connection")
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON Lines")
	cmd.Flags().BoolVar(&includeHeaders, "include-headers", false, "append a trailing headers JSON line (Authorization stripped)")
	cmd.Flags().StringVar(&namespace, "namespace", "default", "vault namespace")
	cmd.Flags().StringVar(&account, "account", "", "account name (multi-account providers)")
	cmd.Flags().BoolVar(&noDaemonStart, "no-daemon-start", false, "do not auto-start keylatchd if not running")
	return cmd
}

// runCallList prints the action catalog for the given connection.
func runCallList(c *cobra.Command, connectionName string, useJSON bool) error {
	tmpl, err := registry.Get(connectionName)
	if err != nil {
		cerr := cmderr.Wrap(
			fmt.Sprintf("provider %q not found", connectionName),
			err,
			"run 'keylatch registry list' to see available providers",
			"KL-3002",
		)
		cmderr.Format(c.ErrOrStderr(), cerr)
		return fmt.Errorf("provider %q not found", connectionName)
	}

	if len(tmpl.Actions) == 0 {
		if useJSON {
			data, _ := json.Marshal(map[string]interface{}{
				"provider": connectionName,
				"actions":  []interface{}{},
			})
			fmt.Fprintln(c.OutOrStdout(), string(data))
		} else {
			fmt.Fprintf(c.OutOrStdout(), "Provider %q has no actions defined.\n", connectionName)
			fmt.Fprintln(c.OutOrStdout(), "Add an 'actions:' block to the provider template to enable keylatch call.")
		}
		return nil
	}

	// Collect and sort action names for deterministic output.
	names := make([]string, 0, len(tmpl.Actions))
	for name := range tmpl.Actions {
		names = append(names, name)
	}
	sort.Strings(names)

	if useJSON {
		type actionEntry struct {
			Name   string `json:"name"`
			Method string `json:"method"`
			Path   string `json:"path"`
		}
		entries := make([]actionEntry, 0, len(names))
		for _, name := range names {
			a := tmpl.Actions[name]
			entries = append(entries, actionEntry{Name: name, Method: a.Method, Path: a.Path})
		}
		data, _ := json.Marshal(map[string]interface{}{
			"provider": connectionName,
			"actions":  entries,
		})
		fmt.Fprintln(c.OutOrStdout(), string(data))
		return nil
	}

	// Human-readable table.
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "Actions for %s:\n\n", connectionName)
	fmt.Fprintf(w, "  NAME\tMETHOD\tPATH\n")
	for _, name := range names {
		a := tmpl.Actions[name]
		fmt.Fprintf(w, "  %s\t%s\t%s\n", name, a.Method, a.Path)
	}
	w.Flush() //nolint:errcheck // output errors are non-critical
	return nil
}

// callResultLine is the JSON Lines output structure for a single action response.
type callResultLine struct {
	StatusCode int             `json:"status_code"`
	DurationMs int64           `json:"duration_ms"`
	Body       json.RawMessage `json:"body"`
}

// callResultLineWithHeaders extends callResultLine with a headers field.
type callResultLineWithHeaders struct {
	callResultLine
	Headers map[string][]string `json:"headers,omitempty"`
}

// printCallResultJSON emits a single JSON Lines record to stdout.
// If includeHeaders is true, the JSON line includes a sanitised headers map
// with the Authorization header stripped to prevent accidental credential leakage.
func printCallResultJSON(c *cobra.Command, statusCode int, durationMs int64, body []byte, headers http.Header, includeHeaders bool) {
	// Try to emit body as raw JSON; fall back to a JSON string if it is not valid JSON.
	var rawBody json.RawMessage
	if json.Valid(body) {
		rawBody = body
	} else {
		quoted, _ := json.Marshal(string(body))
		rawBody = quoted
	}

	line := callResultLine{
		StatusCode: statusCode,
		DurationMs: durationMs,
		Body:       rawBody,
	}

	if includeHeaders && len(headers) > 0 {
		sanitised := make(map[string][]string)
		for k, v := range headers {
			if strings.EqualFold(k, "authorization") {
				continue
			}
			sanitised[k] = v
		}
		out := callResultLineWithHeaders{callResultLine: line, Headers: sanitised}
		data, _ := json.Marshal(out)
		fmt.Fprintln(c.OutOrStdout(), string(data))
		return
	}

	data, _ := json.Marshal(line)
	fmt.Fprintln(c.OutOrStdout(), string(data))
}

// printStructuredError prints an error in structured or human format.
// In JSON mode: {"error":{"code":"...","message":"...","hint":"..."}}
// In human mode: "Error: <message>\n  Hint: <hint>\n"
func printStructuredError(c *cobra.Command, useJSON bool, code, message, hint string) {
	if useJSON {
		data, _ := json.Marshal(map[string]interface{}{
			"error": map[string]string{
				"code":    code,
				"message": message,
				"hint":    hint,
			},
		})
		fmt.Fprintln(c.OutOrStdout(), string(data))
		return
	}
	fmt.Fprintf(c.ErrOrStderr(), "Error: %s\n", message)
	if hint != "" {
		fmt.Fprintf(c.ErrOrStderr(), "  %s\n", hint)
	}
}

// parseProviderAction splits "provider.action" into its components.
// Returns (provider, action, ok). ok is false if the format is invalid.
// Retained for backward compatibility with existing tests and audit code.
func parseProviderAction(s string) (provider, action string, ok bool) {
	for i, r := range s {
		if r == '.' {
			if i == 0 || i == len(s)-1 {
				return "", "", false
			}
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// callMeta is a value-free record of GatewayAction fields for stderr logging.
// Forward-compat: all fields round-tripped; semantics deferred to Phase 9/13.
type callMeta struct {
	Action                 string                    `json:"action"`
	ExchangeStrategy       registry.ExchangeStrategy `json:"exchange_strategy"`
	MaskingProfile         string                    `json:"masking_profile,omitempty"`
	AllowedFields          []string                  `json:"allowed_fields,omitempty"`
	MaxAccessTokenTTL      string                    `json:"max_access_token_ttl,omitempty"`
	RequiredScopes         []string                  `json:"required_scopes,omitempty"`
	UntrustedContentSource bool                      `json:"untrusted_content_source,omitempty"`
	LLMSessionDeny         bool                      `json:"llm_session_deny,omitempty"`
}

// callMetaAllowedFields is the explicit allowlist of JSON keys that are
// permitted in callMeta log output (T-13-06). Fields not in this set must
// never be added to callMeta without updating both this allowlist and the
// lint-callmeta-fields.sh script.
//
// Rationale: this prevents accidental logging of credential-adjacent fields
// (e.g., raw header values, passphrase hints) as callMeta is emitted to
// stderr on every `keylatch call` invocation.
var callMetaAllowedFields = map[string]bool{
	"action":                   true,
	"exchange_strategy":        true,
	"masking_profile":          true,
	"allowed_fields":           true,
	"max_access_token_ttl":     true,
	"required_scopes":          true,
	"untrusted_content_source": true,
	"llm_session_deny":         true,
}

// callMetaFilteredFields returns the subset of callMeta JSON keys that are
// in callMetaAllowedFields, discarding any unknown keys. This is the runtime
// enforcement of the allowlist: if a future callMeta field is added without
// updating callMetaAllowedFields, it will be silently dropped from the log.
func callMetaFilteredFields(m callMeta) map[string]interface{} {
	raw, err := json.Marshal(m)
	if err != nil {
		return map[string]interface{}{}
	}
	var all map[string]interface{}
	if err := json.Unmarshal(raw, &all); err != nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(all))
	for k, v := range all {
		if callMetaAllowedFields[k] {
			out[k] = v
		}
	}
	return out
}

func buildCallMeta(actionName string, action *registry.GatewayAction, strategy registry.ExchangeStrategy) callMeta {
	m := callMeta{
		Action:           actionName,
		ExchangeStrategy: strategy,
	}
	if action != nil {
		m.MaskingProfile = action.MaskingProfile
		m.AllowedFields = action.AllowedFields
		m.MaxAccessTokenTTL = action.MaxAccessTokenTTL
		m.RequiredScopes = action.RequiredScopes
		m.UntrustedContentSource = action.UntrustedContentSource
		m.LLMSessionDeny = action.LLMSessionDeny
	}
	return m
}

// baseURLFromTemplate extracts the scheme+host base URL from a ConnectionTemplate.
// It parses the TestStrategy endpoint and returns just scheme://host.
func baseURLFromTemplate(tmpl registry.ConnectionTemplate) (string, error) {
	endpoint := tmpl.TestStrategy.Endpoint
	if endpoint == "" {
		return "", fmt.Errorf("provider has no test_strategy endpoint configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("endpoint %q has no host", endpoint)
	}
	return u.Scheme + "://" + u.Host, nil
}

// parseParamFlags parses a slice of "key=value" strings into a map.
// Returns an error if any entry does not contain "=".
func parseParamFlags(raw []string) (map[string]string, error) {
	out := make(map[string]string, len(raw))
	for _, kv := range raw {
		idx := strings.Index(kv, "=")
		if idx < 0 {
			return nil, fmt.Errorf("param %q must be in key=value format", kv)
		}
		key := kv[:idx]
		val := kv[idx+1:]
		out[key] = val
	}
	return out, nil
}

// zeroBytes zeroes a byte slice in place.
// Duplicated from connections package to avoid a cross-package import of an unexported symbol.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// emitCallMetaLog logs the allowlisted callMeta fields to stderr.
// This is the T-13-06 audit path for gateway action metadata.
// Retained for compatibility with gateway_actions round-trip.
//
//nolint:unused // preserved for T-13-06 forward-compat; called by Phase 9 gateway dispatch path
func emitCallMetaLog(actionName string, action *registry.GatewayAction, strategy registry.ExchangeStrategy) {
	callMetaVal := buildCallMeta(actionName, action, strategy)
	metaBytes, _ := json.Marshal(callMetaFilteredFields(callMetaVal))
	slog.Info("keylatch call metadata", "metadata", string(metaBytes))
}
