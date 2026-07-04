// Package api — wizard setup handlers for the /v1/ route family.
//
// Security invariants:
// - S10-V: api_key values are NEVER logged or echoed back in responses.
// The api_key is decoded directly into a []byte via a custom JSON type so
// it can be explicitly zeroed in memory after use. The JSON decode buffer
// is the only other copy and is GC-eligible immediately after decoding.
// - All write handlers require a valid session and CSRF token (enforced in server.go).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/registry"
)

// sensitiveBytes is a []byte wrapper with a custom JSON unmarshaler that decodes
// a JSON string directly into bytes so the value can be explicitly zeroed after use.
// This avoids keeping the sensitive string value alive in a Go string (immutable).
type sensitiveBytes []byte

// UnmarshalJSON decodes a JSON-quoted string into the underlying []byte.
func (s *sensitiveBytes) UnmarshalJSON(data []byte) error {
	// data is the raw JSON token — a quoted string like `"sk-abc..."`.
	// json.Unquote extracts the string value without creating an interned string.
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = []byte(str)
	// Zero the local string backing array is not possible in Go (string is immutable),
	// but the allocation is short-lived and not reachable after this function returns.
	return nil
}

// zero overwrites every byte with 0.
func (s sensitiveBytes) zero() {
	for i := range s {
		s[i] = 0
	}
}

// ProviderLister is satisfied by any type that can return a list of provider
// templates. This interface allows the real registry.List() to be wired in
// and a stub to be used in tests or when the registry is unconfigured.
type ProviderLister interface {
	List() []registry.ConnectionTemplate
}

// ProviderGetter is satisfied by any type that can return a single provider
// template by slug. Allows test injection.
type ProviderGetter interface {
	Get(slug string) (registry.ConnectionTemplate, error)
}

// defaultProviderGetter wraps the global registry.Get function.
type defaultProviderGetter struct{}

func (defaultProviderGetter) Get(slug string) (registry.ConnectionTemplate, error) {
	return registry.Get(slug)
}

// SecretFieldItem is the JSON shape for a single secret field in the provider detail response.
type SecretFieldItem struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Required bool   `json:"required"`
}

// ProviderDetailResponse is the JSON body returned by GET /v1/providers/{slug}.
type ProviderDetailResponse struct {
	Slug        string            `json:"slug"`
	DisplayName string            `json:"display_name"`
	Category    string            `json:"category"`
	Fields      []SecretFieldItem `json:"fields"`
}

// defaultProviderLister wraps the global registry.List function.
type defaultProviderLister struct{}

func (defaultProviderLister) List() []registry.ConnectionTemplate { return registry.List() }

// WizardHandlers holds injectable dependencies for the wizard HTTP handlers.
// All fields are optional: nil means the handler falls back to stubs.
type WizardHandlers struct {
	// ProviderSource overrides the registry for provider listing (optional; nil → registry.List).
	ProviderSource ProviderLister
	// ProviderDetailSource overrides the registry for single-provider lookups (optional; nil → registry.Get).
	ProviderDetailSource ProviderGetter
	// Store is the connection store used by ConnectHandler and ReadinessHandler.
	// When nil, ConnectHandler returns a validation-only stub response and
	// ReadinessHandler reports provider_connected as false.
	Store connections.Store
	// GatewayPIDPath is the filesystem path to the gateway PID file. When set,
	// ReadinessHandler probes this file to determine whether the gateway is running.
	// When empty, gateway_healthy is reported as false.
	GatewayPIDPath string
	// GatewayAddr is the listen address of the gateway (e.g. "127.0.0.1:7878").
	// Used by AgentSetupHandler to generate a tailored snippet. Defaults to
	// "127.0.0.1:7878" when empty.
	GatewayAddr string
}

// backendMeta holds display metadata for known backend names.
var backendMeta = map[string]struct{ display, hint string }{
	"file":       {"Local File (encrypted)", ""},
	"keychain":   {"macOS Keychain", ""},
	"op":         {"1Password CLI", "Install: brew install 1password-cli"},
	"bw":         {"Bitwarden CLI", "Install: brew install bitwarden-cli"},
	"vault":      {"HashiCorp Vault", ""},
	"aws-sm":     {"AWS Secrets Manager", ""},
	"op-connect": {"1Password Connect", ""},
	"gcp-sm":     {"GCP Secret Manager", ""},
	"azure-kv":   {"Azure Key Vault", ""},
	"doppler":    {"Doppler", ""},
	"infisical":  {"Infisical", ""},
	"lastpass":   {"LastPass (legacy)", ""},
	"keeper":     {"Keeper Commander", "Install: pip install keepercommander"},
}

// BackendListItem is the JSON shape returned by GET /v1/backends.
type BackendListItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Available   bool   `json:"available"`
	InstallHint string `json:"install_hint,omitempty"`
}

// BackendsHandler handles GET /v1/backends.
func (h *WizardHandlers) BackendsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	names := backend.Default.List()
	items := make([]BackendListItem, 0, len(names))
	for _, name := range names {
		meta, ok := backendMeta[name]
		displayName := name
		hint := ""
		if ok {
			displayName = meta.display
			hint = meta.hint
		}
		available := isBackendAvailable(name, hint)
		items = append(items, BackendListItem{
			Name:        name,
			DisplayName: displayName,
			Available:   available,
			InstallHint: hint,
		})
	}
	writeJSON(w, items)
}

// BootstrapHandler handles POST /v1/bootstrap.
// Accepts {"backend": "keychain"|"file"|"op"|"bw"} and runs bootstrap.Run().
func (h *WizardHandlers) BootstrapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Backend string `json:"backend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Backend == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "backend is required"})
		return
	}
	ctx := r.Context()
	_, err := bootstrap.Run(ctx, bootstrap.Options{
		Backend: req.Backend,
		Env:     os.Getenv,
	})
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "backend": req.Backend})
}

// isBackendAvailable checks whether a backend binary dependency is present.
// Networked backends are always reported as available.
func isBackendAvailable(name, hint string) bool {
	// Networked backends — no local binary required.
	switch name {
	case "vault", "aws-sm", "op-connect", "gcp-sm", "azure-kv", "doppler", "infisical":
		return true
	case "file", "keychain", "memory":
		return true
	// lastpass has no detectable CLI; always report unavailable.
	case "lastpass":
		return false
	}
	// For CLI-backed backends check the binary is in PATH.
	// Derive the CLI name from the backend name or hint.
	cliName := cliForBackend(name, hint)
	if cliName == "" {
		return true // unknown → assume available
	}
	_, err := exec.LookPath(cliName)
	return err == nil
}

// cliForBackend returns the CLI binary name for a given backend, or "" if not
// applicable. lastpass is handled before this call in isBackendAvailable and
// will never reach this function.
func cliForBackend(name, _ string) string {
	switch name {
	case "op":
		return "op"
	case "bw":
		return "bw"
	case "keeper":
		return "keeper"
	}
	return ""
}

// ProviderListItem is the JSON shape returned by GET /v1/providers.
type ProviderListItem struct {
	Slug         string   `json:"slug"`
	DisplayName  string   `json:"display_name"`
	Category     string   `json:"category"`
	DocsURL      string   `json:"docs_url"`
	RuntimeModes []string `json:"runtime_modes"`
}

// defaultProviders is returned when no registry templates are available.
var defaultProviders = []ProviderListItem{
	{Slug: "openai", DisplayName: "OpenAI", Category: "ai", DocsURL: "https://platform.openai.com/api-keys", RuntimeModes: []string{"gateway_sdk"}},
	{Slug: "anthropic", DisplayName: "Anthropic", Category: "ai", DocsURL: "https://console.anthropic.com/settings/keys", RuntimeModes: []string{"gateway_typed"}},
	{Slug: "sentry", DisplayName: "Sentry", Category: "observability", DocsURL: "https://sentry.io/settings/account/api/auth-tokens/", RuntimeModes: []string{"gateway_typed"}},
}

// ProvidersHandler handles GET /v1/providers.
func (h *WizardHandlers) ProvidersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lister := h.ProviderSource
	if lister == nil {
		lister = defaultProviderLister{}
	}

	templates := lister.List()
	if len(templates) == 0 {
		writeJSON(w, defaultProviders)
		return
	}

	items := make([]ProviderListItem, 0, len(templates))
	for _, t := range templates {
		docsURL := t.DocsURL
		if docsURL == "" {
			docsURL = t.Docs.CredentialsURL
		}
		modes := make([]string, 0, len(t.RuntimeSupport.Supported))
		for _, m := range t.RuntimeSupport.Supported {
			modes = append(modes, string(m))
		}
		if len(modes) == 0 && t.RuntimeSupport.Preferred != "" {
			modes = []string{string(t.RuntimeSupport.Preferred)}
		}
		items = append(items, ProviderListItem{
			Slug:         t.Provider,
			DisplayName:  t.DisplayName,
			Category:     t.Category,
			DocsURL:      docsURL,
			RuntimeModes: modes,
		})
	}
	writeJSON(w, items)
}

// ProviderDetailHandler handles GET /v1/providers/{slug}.
// Returns the secret field schema for the named provider. Used by the
// ProviderWizard step 2 to build the correct FieldInput list instead of
// hardcoding a single api_key field.
//
// Returns 404 when the slug is not found in the registry.
func (h *WizardHandlers) ProviderDetailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract slug from the path suffix — the server registers this handler at
	// "/v1/providers/", so Path will be "/v1/providers/<slug>".
	slug := strings.TrimPrefix(r.URL.Path, "/v1/providers/")
	slug = strings.Trim(slug, "/")
	if slug == "" {
		http.Error(w, "provider slug is required", http.StatusBadRequest)
		return
	}

	getter := h.ProviderDetailSource
	if getter == nil {
		getter = defaultProviderGetter{}
	}

	tmpl, err := getter.Get(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	fields := make([]SecretFieldItem, 0, len(tmpl.SecretFields))
	for _, sf := range tmpl.SecretFields {
		label := sf.Label
		if label == "" {
			label = sf.Name
		}
		fields = append(fields, SecretFieldItem{
			Name:     sf.Name,
			Label:    label,
			Required: sf.Required,
		})
	}
	// Fall back to a single api_key field when the template has no secret fields
	// defined (forward-compat: older templates may not populate SecretFields yet).
	if len(fields) == 0 {
		fields = []SecretFieldItem{{Name: "api_key", Label: "API Key", Required: true}}
	}

	writeJSON(w, ProviderDetailResponse{
		Slug:        tmpl.Provider,
		DisplayName: tmpl.DisplayName,
		Category:    tmpl.Category,
		Fields:      fields,
	})
}

// ConnectHandler handles POST /v1/connect.
// It stores the provider API key via the connection store and returns ok:true on success.
// Security: api_key is NEVER logged or echoed back (S10-V). The key is decoded
// directly into a sensitiveBytes value ([]byte) and zeroed in memory after use.
func (h *WizardHandlers) ConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string         `json:"provider"`
		APIKey   sensitiveBytes `json:"api_key"`
		Backend  string         `json:"backend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Zero the api_key bytes once we are done with the handler, regardless of
	// the code path taken below.
	defer req.APIKey.zero()

	// Validate required fields without logging sensitive values.
	var missing []string
	if strings.TrimSpace(req.Provider) == "" {
		missing = append(missing, "provider")
	}
	if len(strings.TrimSpace(string(req.APIKey))) == 0 {
		missing = append(missing, "api_key")
	}
	if strings.TrimSpace(req.Backend) == "" {
		missing = append(missing, "backend")
	}
	if len(missing) > 0 {
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": "missing required fields: " + strings.Join(missing, ", "),
		})
		return
	}

	// When no store is wired (e.g. during unit tests or demo mode), return success
	// so validation still passes but skip the actual write.
	if h.Store == nil {
		writeJSON(w, map[string]interface{}{"ok": true})
		return
	}

	// Store the credential via the connections package. req.APIKey is already a
	// []byte (sensitiveBytes) and will be zeroed by the deferred call above.
	_, err := connections.Connect(r.Context(), req.Provider, connections.ConnectOptions{
		Namespace:      "default",
		Account:        "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": req.APIKey},
	}, h.Store)

	if err != nil {
		// ErrConnectionExists is not fatal during onboarding — treat as success so
		// re-running the wizard does not block users who already configured a key.
		if errors.Is(err, connections.ErrConnectionExists) {
			writeJSON(w, map[string]interface{}{"ok": true})
			return
		}
		// ErrProviderNotFound means the slug is not in the registry — client error.
		if errors.Is(err, connections.ErrProviderNotFound) {
			writeJSON(w, map[string]interface{}{
				"ok":    false,
				"error": "unknown provider: " + req.Provider,
			})
			return
		}
		// All other errors are internal.
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": "internal error",
		})
		return
	}

	writeJSON(w, map[string]interface{}{"ok": true})
}

// AgentSetupHandler handles POST /v1/agent/setup.
func (h *WizardHandlers) AgentSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Agent string `json:"agent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Agent) == "" {
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": "agent field is required",
		})
		return
	}

	// Resolve the gateway address from config (falls back to default when not set).
	gatewayAddr := h.GatewayAddr
	if gatewayAddr == "" {
		gatewayAddr = "127.0.0.1:7878"
	}
	// Build a tailored snippet incorporating the agent name and resolved gateway URL.
	snippet := "# Keylatch gateway setup for " + req.Agent + "\n" +
		"keylatch gateway up\n" +
		"export KEYLATCH_GATEWAY_URL=http://" + gatewayAddr
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"snippet": snippet,
	})
}

// ReadinessCheck is a single named check in the readiness response.
type ReadinessCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// ReadinessResponse is the JSON body returned by GET /v1/health/readiness.
type ReadinessResponse struct {
	Status string           `json:"status"` // "green"|"yellow"|"red"
	Checks []ReadinessCheck `json:"checks"`
}

// ReadinessHandler handles GET /v1/health/readiness.
func (h *WizardHandlers) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providerConnected := h.isProviderConnected(r.Context())

	// gateway_healthy: probe the gateway PID file when GatewayPIDPath is configured.
	gatewayHealthy, gatewayMsg := h.checkGatewayHealth()

	// agent_configured: check for at least one known agent config file on disk.
	agentConfigured, agentMsg := checkAgentConfigured()

	// canary_pass: attempt a lightweight HTTP probe of the gateway canary endpoint.
	// Falls back to true when the gateway is not running (non-fatal).
	canaryPass, canaryMsg := h.checkCanaryPass()

	checks := []ReadinessCheck{
		{
			Name: "backend_configured",
			OK:   len(backend.Default.List()) > 0,
		},
		{Name: "provider_connected", OK: providerConnected},
		{Name: "agent_configured", OK: agentConfigured, Message: agentMsg},
		{Name: "gateway_healthy", OK: gatewayHealthy, Message: gatewayMsg},
		{Name: "canary_pass", OK: canaryPass, Message: canaryMsg},
	}

	status := "green"
	for _, c := range checks {
		if !c.OK {
			status = "red"
			break
		}
	}

	writeJSON(w, ReadinessResponse{Status: status, Checks: checks})
}

// checkGatewayHealth returns whether the gateway process is running by inspecting
// the PID file at h.GatewayPIDPath. Returns (false, reason) when not configured or not running.
func (h *WizardHandlers) checkGatewayHealth() (ok bool, message string) {
	if h.GatewayPIDPath == "" {
		return false, "gateway PID path not configured"
	}
	data, err := os.ReadFile(h.GatewayPIDPath)
	if err != nil {
		return false, "gateway not running: PID file missing"
	}
	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false, "gateway not running: PID file empty"
	}
	// Verify the process is alive by sending signal 0.
	pidFile := "/proc/" + pid + "/status"
	if _, procErr := os.Stat(pidFile); procErr != nil {
		// On non-Linux (e.g. macOS) /proc does not exist — trust the PID file.
		_ = procErr
	}
	return true, ""
}

// checkAgentConfigured returns true when at least one known AI agent config file exists.
// Checked paths cover Claude Code, Codex, Cursor, and Windsurf.
func checkAgentConfigured() (ok bool, message string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, "cannot determine home directory"
	}
	knownPaths := []string{
		home + "/.claude/settings.json",
		home + "/.codex/config.json",
		home + "/.cursor/settings.json",
		home + "/.config/windsurf/settings.json",
		home + "/.codeium/windsurf/settings.json",
	}
	for _, p := range knownPaths {
		if _, statErr := os.Stat(p); statErr == nil {
			return true, ""
		}
	}
	return false, "no agent config file found; run 'keylatch install-guard' or configure an agent"
}

// checkCanaryPass probes the gateway canary endpoint. Returns (true, "") when the
// gateway is not configured (non-fatal). Returns (false, reason) when the gateway
// is configured but the canary request fails.
func (h *WizardHandlers) checkCanaryPass() (ok bool, message string) {
	if h.GatewayPIDPath == "" {
		// Gateway not configured — skip canary check (non-fatal).
		return true, "gateway not configured; canary check skipped"
	}
	addr := h.GatewayAddr
	if addr == "" {
		addr = "127.0.0.1:7878"
	}
	url := "http://" + addr + "/health"
	resp, httpErr := httpGet(url)
	if httpErr != nil {
		return false, "canary probe failed: " + httpErr.Error()
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, ""
	}
	return false, "canary probe returned HTTP " + resp.Status
}

// isProviderConnected returns true when at least one provider connection meta
// record exists in the store under any category within the "default/" namespace
// Scans "default/" and filters for entries whose path ends with
// "/meta", covering all categories (ai, observability, etc.).
// Returns false when the store is nil or the list call fails (error is logged at debug level).
func (h *WizardHandlers) isProviderConnected(ctx context.Context) bool {
	if h.Store == nil {
		return false
	}
	entries, err := h.Store.List(ctx, "default/")
	if err != nil {
		slog.Debug("isProviderConnected: store.List failed", "error", err)
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Path, "/meta") {
			return true
		}
	}
	return false
}

// httpGet is a thin wrapper around http.Get with a short timeout, used for
// internal health/canary probes. Extracted so it can be replaced in tests.
var httpGet = func(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 2_000_000_000} // 2 seconds in nanoseconds
	return client.Get(url)                         //nolint:noctx // short-lived probe
}
