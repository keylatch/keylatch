// Package api implements the keylatch UI HTTP API handlers.
//
// Security invariants:
//   - S10-V: no credential values are ever returned in responses (value-free).
//   - Canary tests verify this on every handler.
//   - All write handlers require a valid session and CSRF token.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/registry"
)

// FieldMode is the storage mode for a single credential field.
type FieldMode string

const (
	// FieldModeDirect means the field value is encrypted in the keylatch vault.
	FieldModeDirect FieldMode = "direct"
	// FieldModeReference means the field is a URI referencing an external PM.
	FieldModeReference FieldMode = "reference"
)

// ConnectionField is a single field entry in the enriched connections response.
// Value-free: no secret value is ever included.
type ConnectionField struct {
	Name string    `json:"name"`
	Mode FieldMode `json:"mode"`
	// URI is only populated when Mode == FieldModeReference.
	URI string `json:"uri,omitempty"`
}

// connectionPolicyPath returns the vault path for per-provider approval policy.
// NOTE: like fieldModesPath and connectionMetaPath, the account segment is not
// included — policy is stored at the provider level, shared by all accounts of
// that provider. This is intentional for the v1 keylatch model where a single
// provider slug maps to one identity.
func connectionPolicyPath(namespace, provider, _ string) string {
	if namespace == "" {
		namespace = defaultConnectionNamespace
	}
	cat := providerCategory(provider)
	return fmt.Sprintf("%s/%s/%s/policy", namespace, cat, provider)
}

// connectionPolicy holds the persisted approval policy override for a connection.
type connectionPolicy struct {
	ApprovalPolicy string `json:"approval_policy"`
}

// loadConnectionPolicy reads the stored approval policy for a connection.
// Returns "" (meaning "use global default") when no override has been stored.
func loadConnectionPolicy(r *http.Request, store connections.Store, namespace, provider, account string) string {
	data, _, err := store.Get(r.Context(), connectionPolicyPath(namespace, provider, account))
	if err != nil {
		return ""
	}
	var p connectionPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return ""
	}
	return p.ApprovalPolicy
}

// saveConnectionPolicy persists the approval policy override for a connection.
func saveConnectionPolicy(r *http.Request, store connections.Store, namespace, provider, account, policy string) error {
	path := connectionPolicyPath(namespace, provider, account)
	data, err := json.Marshal(connectionPolicy{ApprovalPolicy: policy})
	if err != nil {
		return err
	}
	return store.Set(r.Context(), path, data, backend.Meta{
		Path:    path,
		Backend: "vault",
		Version: 1,
	})
}

// fieldModesPath returns the vault path for per-field mode metadata.
// Canonical format: namespace/category/provider/fieldmodes (S-FIND-23),
// matching connectionMetaPath and secretFieldPath.
func fieldModesPath(namespace, provider, _ string) string {
	if namespace == "" {
		namespace = defaultConnectionNamespace
	}
	cat := providerCategory(provider)
	return fmt.Sprintf("%s/%s/%s/fieldmodes", namespace, cat, provider)
}

// loadFieldModes reads stored field-mode metadata for a connection.
// Returns an empty map (not an error) when no metadata has been stored yet.
func loadFieldModes(r *http.Request, store connections.Store, namespace, provider, account string) map[string]ConnectionField {
	data, _, err := store.Get(r.Context(), fieldModesPath(namespace, provider, account))
	if err != nil {
		return make(map[string]ConnectionField)
	}
	var m map[string]ConnectionField
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]ConnectionField)
	}
	return m
}

// saveFieldModes writes per-field mode metadata to the store.
func saveFieldModes(r *http.Request, store connections.Store, namespace, provider, account string, modes map[string]ConnectionField) error {
	data, err := json.Marshal(modes)
	if err != nil {
		return fmt.Errorf("marshal field modes: %w", err)
	}
	path := fieldModesPath(namespace, provider, account)
	return store.Set(r.Context(), path, data, backend.Meta{
		Path:    path,
		Backend: "vault",
		Version: 1,
	})
}

// defaultConnectionNamespace is the store path prefix for all connection entries.
const defaultConnectionNamespace = "default"

// ConnectionsHandler handles GET /api/connections and POST /api/connections.
// Value-free: no credential values are returned.
type ConnectionsHandler struct {
	Store       connections.Store
	AuditLogger *audit.Logger
}

// ServeHTTP dispatches based on method.
func (h *ConnectionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// connListItem is the JSON shape for a connection in the list response.
// Value-free: no credential values are ever included (S10-V).
type connListItem struct {
	// ID is a stable identifier derived from namespace/provider/account.
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Provider       string            `json:"provider"`
	Account        string            `json:"account"`
	Namespace      string            `json:"namespace"`
	Status         string            `json:"status"`
	Fields         []ConnectionField `json:"fields"`
	CreatedAt      string            `json:"created_at,omitempty"`
	UpdatedAt      string            `json:"updated_at,omitempty"`
	ApprovalPolicy string            `json:"approval_policy,omitempty"` // "" = global default
}

// list returns all connections (value-free) with per-field storage mode metadata.
func (h *ConnectionsHandler) list(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.Store == nil {
		writeJSON(w, map[string]interface{}{"connections": []interface{}{}})
		return
	}

	statuses, err := connections.Status(r.Context(), connections.StatusOptions{Namespace: defaultConnectionNamespace}, h.Store)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// NOTE: per-connection field-mode reads; O(N) is acceptable for Tauri desktop (small N).
	items := make([]connListItem, 0, len(statuses))
	for _, status := range statuses {
		conn := status.Connection

		// Load per-field mode metadata (never errors — returns empty map on miss).
		fieldModes := loadFieldModes(r, h.Store, conn.Namespace, conn.Provider, conn.Account)

		fields := make([]ConnectionField, 0, len(conn.Fields))
		for _, name := range conn.Fields {
			if cf, ok := fieldModes[name]; ok {
				fields = append(fields, cf)
			} else {
				fields = append(fields, ConnectionField{Name: name, Mode: FieldModeDirect})
			}
		}

		createdAt := ""
		updatedAt := ""
		if !conn.CreatedAt.IsZero() {
			createdAt = conn.CreatedAt.Format("2006-01-02T15:04:05Z")
		}
		if !conn.UpdatedAt.IsZero() {
			updatedAt = conn.UpdatedAt.Format("2006-01-02T15:04:05Z")
		}

		// Load per-connection approval policy override (never errors — returns "" on miss).
		approvalPolicy := loadConnectionPolicy(r, h.Store, conn.Namespace, conn.Provider, conn.Account)

		items = append(items, connListItem{
			ID:             connectionID(conn.Namespace, conn.Provider, conn.Account),
			Name:           connectionName(conn.Provider, conn.Account),
			Provider:       conn.Provider,
			Account:        conn.Account,
			Namespace:      conn.Namespace,
			Status:         conn.Status,
			Fields:         fields,
			CreatedAt:      createdAt,
			UpdatedAt:      updatedAt,
			ApprovalPolicy: approvalPolicy,
		})
	}
	writeJSON(w, map[string]interface{}{"connections": items})
}

// connectionID returns a stable ID string for a connection.
func connectionID(namespace, provider, account string) string {
	if namespace == "" {
		namespace = "default"
	}
	if account == "" {
		account = "default"
	}
	return namespace + "/" + provider + "/" + account
}

// createFieldReq is the per-field entry in a POST /api/connections request.
type createFieldReq struct {
	Name string    `json:"name"`
	Mode FieldMode `json:"mode"`
	// Value is only used when Mode == "direct" (never echoed back in responses).
	Value string `json:"value,omitempty"`
	// URI is only used when Mode == "reference".
	URI string `json:"uri,omitempty"`
}

func (h *ConnectionsHandler) create(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		http.Error(w, "connection store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Decode into a raw map first so we can handle both the legacy
	// "fields": {"key": "value"} shape and the new "fields": [{name,mode,...}] shape.
	var rawReq struct {
		Provider    string          `json:"provider"`
		Account     string          `json:"account"`
		Namespace   string          `json:"namespace"`
		Runtime     string          `json:"runtime"`
		FieldsRaw   json.RawMessage `json:"fields"`
		LegacyName  string          `json:"name"`
		LegacyValue string          `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if rawReq.Provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}

	// Parse fields: try array format first, fall back to legacy map format.
	var typedFields []createFieldReq
	var legacyMap map[string]string
	if len(rawReq.FieldsRaw) > 0 {
		// Detect shape by first non-whitespace byte.
		firstByte := firstNonSpace(rawReq.FieldsRaw)
		switch firstByte {
		case '[':
			if err := json.Unmarshal(rawReq.FieldsRaw, &typedFields); err != nil {
				http.Error(w, "invalid fields array", http.StatusBadRequest)
				return
			}
		case '{':
			if err := json.Unmarshal(rawReq.FieldsRaw, &legacyMap); err != nil {
				http.Error(w, "invalid fields map", http.StatusBadRequest)
				return
			}
		}
	}

	// Validate reference URIs before any store writes.
	var validationErrors []FieldValidationError
	for _, f := range typedFields {
		if f.Mode == FieldModeReference {
			if ve := ValidateRefURI(f.Name, f.URI); ve != nil {
				validationErrors = append(validationErrors, *ve)
			}
		}
	}
	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": validationErrors})
		return
	}

	// Build direct-mode fields map for the core connections.Connect call.
	// Reference-mode fields store the URI in the vault so the required-field
	// check passes; the real value is resolved at runtime via EPIC-05 resolver.
	directFields := make(map[string][]byte)
	for _, f := range typedFields {
		switch f.Mode {
		case FieldModeDirect:
			if f.Value != "" {
				directFields[f.Name] = []byte(f.Value)
			}
		case FieldModeReference:
			directFields[f.Name] = []byte(f.URI)
		default:
			// No explicit mode — treat as direct.
			if f.Value != "" {
				directFields[f.Name] = []byte(f.Value)
			}
		}
	}
	// Legacy flat-map fields — treat as direct.
	for k, v := range legacyMap {
		directFields[k] = []byte(v)
	}
	if rawReq.LegacyName != "" && rawReq.LegacyValue != "" {
		directFields[rawReq.LegacyName] = []byte(rawReq.LegacyValue)
	}

	conn, err := connections.Connect(r.Context(), rawReq.Provider, connections.ConnectOptions{
		Namespace:      rawReq.Namespace,
		Account:        rawReq.Account,
		Mode:           registry.RuntimeMode(rawReq.Runtime),
		NonInteractive: true,
		Fields:         directFields,
	}, h.Store)
	if errors.Is(err, connections.ErrConnectionExists) || errors.Is(err, connections.ErrAmbiguous) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store per-field mode metadata (reference URIs + direct markers).
	if len(typedFields) > 0 {
		ns := conn.Namespace
		modes := make(map[string]ConnectionField, len(typedFields))
		for _, f := range typedFields {
			cf := ConnectionField{Name: f.Name, Mode: f.Mode}
			if f.Mode == FieldModeReference {
				cf.URI = f.URI
			}
			modes[f.Name] = cf
		}
		if saveErr := saveFieldModes(r, h.Store, ns, conn.Provider, conn.Account, modes); saveErr != nil {
			// Non-fatal: the connection was created successfully but field-mode metadata
			// could not be saved.  Log the error and include a warning in the response so
			// the caller knows to re-edit the connection to restore the modes.
			slog.Error("connections: failed to save field modes",
				"provider", conn.Provider,
				"error", saveErr,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       connectionID(ns, conn.Provider, conn.Account),
				"warnings": []string{"field modes could not be saved; re-edit to set them"},
			})
			return
		}
	}

	writeJSON(w, conn)
}

func connectionName(provider, account string) string {
	if account == "" || account == "default" {
		return provider
	}
	return provider + "/" + account
}

func parseConnectionName(name string) (provider, account string) {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	if len(parts) > 0 {
		provider = parts[0]
	}
	account = "default"
	if len(parts) > 1 && parts[1] != "" {
		account = parts[1]
	}
	return provider, account
}

// providerCategory returns the category for a provider slug, defaulting to "ai".
func providerCategory(provider string) string {
	tmpl, err := registry.Get(provider)
	if err != nil || tmpl.Category == "" {
		return "ai"
	}
	return tmpl.Category
}

// connectionMetaPath returns the canonical vault path for connection metadata.
// Canonical format: namespace/category/provider/meta (S-FIND-23).
func connectionMetaPath(namespace, provider, _ string) string {
	if namespace == "" {
		namespace = defaultConnectionNamespace
	}
	cat := providerCategory(provider)
	return fmt.Sprintf("%s/%s/%s/meta", namespace, cat, provider)
}

// secretFieldPath returns the canonical vault path for a secret field.
// Canonical format: namespace/category/provider/field (S-FIND-23).
func secretFieldPath(namespace, provider, _ string, field string) string {
	if namespace == "" {
		namespace = defaultConnectionNamespace
	}
	cat := providerCategory(provider)
	return fmt.Sprintf("%s/%s/%s/%s", namespace, cat, provider, field)
}

func loadConnectionMetadata(r *http.Request, store connections.Store, name string) (*connections.Connection, error) {
	provider, account := parseConnectionName(name)
	if provider == "" {
		return nil, backend.ErrNotFound
	}
	data, _, err := store.Get(r.Context(), connectionMetaPath(defaultConnectionNamespace, provider, account))
	if err != nil {
		return nil, err
	}
	var conn connections.Connection
	if err := json.Unmarshal(data, &conn); err != nil {
		return nil, err
	}
	return &conn, nil
}

func rotateConnectionField(r *http.Request, store connections.Store, name, field string) error {
	var req struct {
		Value string `json:"value"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Value == "" {
		return fmt.Errorf("new field value is required")
	}
	provider, account := parseConnectionName(name)
	if provider == "" || field == "" {
		return fmt.Errorf("connection and field are required")
	}
	return store.Set(r.Context(), secretFieldPath(defaultConnectionNamespace, provider, account, field), []byte(req.Value), backend.Meta{
		Path:    secretFieldPath(defaultConnectionNamespace, provider, account, field),
		Backend: "vault",
		Version: 1,
	})
}

// ConnectionDetailHandler handles GET/DELETE /api/connections/{name}
// and POST /api/connections/{name}/fields/{field}/rotate.
type ConnectionDetailHandler struct {
	Store         connections.Store
	AuditLogger   *audit.Logger
	RuntimeTester *RuntimeTestHandler
}

// ServeHTTP dispatches based on method and path suffix.
func (h *ConnectionDetailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/connections/")
	if strings.HasSuffix(path, "/test") {
		tester := h.RuntimeTester
		if tester == nil {
			tester = &RuntimeTestHandler{Store: h.Store}
		}
		tester.ServeHTTP(w, r)
		return
	}
	parts := strings.SplitN(path, "/", 3)
	name := parts[0]

	if len(parts) == 3 && parts[1] == "fields" && strings.HasSuffix(parts[2], "/rotate") {
		field := strings.TrimSuffix(parts[2], "/rotate")
		h.rotateField(w, r, name, field)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.get(w, r, name)
	case http.MethodPut:
		h.update(w, r, name)
	case http.MethodDelete:
		h.delete(w, r, name)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// get returns connection metadata (value-free).
// If the store has an entry for this connection, return its name; otherwise 404.
func (h *ConnectionDetailHandler) get(w http.ResponseWriter, r *http.Request, name string) {
	if h.Store == nil {
		http.Error(w, "connection store unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, err := loadConnectionMetadata(r, h.Store, name)
	if errors.Is(err, backend.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, conn)
}

// update replaces the per-field mode metadata for an existing connection.
// Direct field values can also be rotated in the same call.
// Value-free: Values are written but never echoed back.
func (h *ConnectionDetailHandler) update(w http.ResponseWriter, r *http.Request, name string) {
	if h.Store == nil {
		http.Error(w, "connection store unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, err := loadConnectionMetadata(r, h.Store, name)
	if errors.Is(err, backend.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var req struct {
		Fields         []createFieldReq `json:"fields"`
		ApprovalPolicy *string          `json:"approval_policy"` // nil = not changing
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate reference URIs.
	var validationErrors []FieldValidationError
	for _, f := range req.Fields {
		if f.Mode == FieldModeReference {
			if ve := ValidateRefURI(f.Name, f.URI); ve != nil {
				validationErrors = append(validationErrors, *ve)
			}
		}
	}
	if len(validationErrors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": validationErrors})
		return
	}

	// Validate approval_policy BEFORE any store writes so an invalid value
	// cannot leave behind orphaned secret writes (partial-write guard).
	if req.ApprovalPolicy != nil {
		validPolicies := map[string]bool{
			"":          true,
			"global":    true,
			"prompt":    true,
			"first-run": true,
			"trust":     true,
		}
		if !validPolicies[*req.ApprovalPolicy] {
			http.Error(w, "invalid approval_policy value", http.StatusBadRequest)
			return
		}
	}

	// Resolve namespace consistently: prefer conn.Namespace, fall back to the
	// package default.  This avoids the C-04 bug where secretFieldPath used
	// defaultConnectionNamespace while saveFieldModes/loadFieldModes used conn.Namespace.
	ns := conn.Namespace
	if ns == "" {
		ns = defaultConnectionNamespace
	}

	// Validate all fields and persist field-mode metadata BEFORE writing secret
	// values.  If saveFieldModes fails, we return 500 without writing any secrets
	// (non-atomic write guard — W-05).
	newModes := loadFieldModes(r, h.Store, ns, conn.Provider, conn.Account)
	for _, f := range req.Fields {
		cf := ConnectionField{Name: f.Name, Mode: f.Mode}
		if f.Mode == FieldModeReference {
			cf.URI = f.URI
		}
		newModes[f.Name] = cf
	}
	if saveErr := saveFieldModes(r, h.Store, ns, conn.Provider, conn.Account, newModes); saveErr != nil {
		http.Error(w, "could not save field metadata", http.StatusInternalServerError)
		return
	}

	// Write updated direct-mode field values only after metadata is persisted.
	for _, f := range req.Fields {
		if f.Mode == FieldModeDirect && f.Value != "" {
			path := secretFieldPath(ns, conn.Provider, conn.Account, f.Name)
			if setErr := h.Store.Set(r.Context(), path, []byte(f.Value), backend.Meta{
				Path:    path,
				Backend: "vault",
				Version: 1,
			}); setErr != nil {
				http.Error(w, "store error", http.StatusInternalServerError)
				return
			}
		}
	}

	// Persist approval policy override when explicitly provided.
	// Validation already performed above before any store writes.
	if req.ApprovalPolicy != nil {
		if saveErr := saveConnectionPolicy(r, h.Store, ns, conn.Provider, conn.Account, *req.ApprovalPolicy); saveErr != nil {
			http.Error(w, "could not save approval policy", http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]string{"status": "updated", "id": connectionID(ns, conn.Provider, conn.Account)})
}

// delete removes a connection.
func (h *ConnectionDetailHandler) delete(w http.ResponseWriter, r *http.Request, name string) {
	if h.Store == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	provider, account := parseConnectionName(name)
	if err := connections.Delete(r.Context(), provider, account, defaultConnectionNamespace, h.Store); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ConnectionDetailHandler) rotateField(w http.ResponseWriter, r *http.Request, name, field string) {
	if h.Store == nil {
		http.Error(w, "connection store unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := rotateConnectionField(r, h.Store, name, field); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "rotated", "field": field})
}

// ClearConnectionsHandler handles POST /api/connections/clear.
// Phase 10 stub: returns 501 until a full implementation is wired.
type ClearConnectionsHandler struct{}

func (h *ClearConnectionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNotImplemented)
	writeJSON(w, map[string]string{"error": "not_implemented"})
}

// writeJSON writes v as JSON to w, setting Content-Type.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// firstNonSpace returns the first non-whitespace byte in b, or 0 if b is empty/blank.
func firstNonSpace(b []byte) byte {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c
		}
	}
	return 0
}
