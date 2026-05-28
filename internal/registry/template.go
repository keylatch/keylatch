// Package registry defines the canonical typed Go struct model for all provider
// entries. It is the foundational data layer for Phase 3: every other package
// (connections, mcp, agentsnippet, agent) reads from it.
//
// The registry ships as compiled-in Go structs for Core-v1 templates; community
// bundle loading via LoadBundle is included with mandatory cosign signature
// verification (FIND-008).
package registry

import "github.com/keylatch/keylatch/internal/template"

// TrustLevel classifies the provenance of a provider template.
type TrustLevel int

const (
	TrustCore                  TrustLevel = iota // built-in Core v1 template
	TrustVerifiedCommunity                       // community template with verified signature
	TrustCommunityExperimental                   // community template, experimental/unsigned
	TrustLocalOnly                               // local-only development template
	TrustInternal                                // internal/private template
)

// RuntimeMode identifies how the CLI interacts with credentials for a provider.
// Exactly four valid values; deprecated values (direct_run, local_gateway,
// hosted_gateway) MUST NOT appear in this enum.
type RuntimeMode string

const (
	RuntimeGatewayTyped   RuntimeMode = "gateway_typed"
	RuntimeGatewaySDK     RuntimeMode = "gateway_sdk"
	RuntimeDirectBrokered RuntimeMode = "direct_brokered"
	RuntimeGatewayProxy   RuntimeMode = "gateway_proxy"
)

// validRuntimeModes is the closed set of valid RuntimeMode values.
// S3-15(b): any RuntimeSupport.Supported entry must be in this set.
var validRuntimeModes = map[RuntimeMode]struct{}{
	RuntimeGatewayTyped:   {},
	RuntimeGatewaySDK:     {},
	RuntimeDirectBrokered: {},
	RuntimeGatewayProxy:   {},
}

// IsValidRuntimeMode returns true if m is one of the four valid RuntimeMode values.
func IsValidRuntimeMode(m RuntimeMode) bool {
	_, ok := validRuntimeModes[m]
	return ok
}

// AuthFlow describes how the provider authenticates.
type AuthFlow string

const (
	AuthAPIKey       AuthFlow = "api_key"
	AuthOAuthBrowser AuthFlow = "oauth_browser"
	AuthOAuthDevice  AuthFlow = "oauth_device"
	AuthBasic        AuthFlow = "basic"
	AuthBearer       AuthFlow = "bearer"
	AuthCertificate  AuthFlow = "certificate"
	AuthCustom       AuthFlow = "custom"
)

// ExchangeStrategy describes how a GatewayAction exchanges credentials.
type ExchangeStrategy string

const (
	ExchangeStaticGatewayOnly ExchangeStrategy = "static_gateway_only"
	ExchangeDynamicJWT        ExchangeStrategy = "dynamic_jwt"
	ExchangeOAuthRefresh      ExchangeStrategy = "oauth_refresh"
	ExchangeNone              ExchangeStrategy = "none"
)

// RuntimeSupport describes the runtime modes a provider supports.
// DefaultRuntime, RuntimeReason, and GatewaySupported are derived backward-compat
// views computed from Preferred and Supported.
type RuntimeSupport struct {
	Preferred RuntimeMode   `json:"preferred"          yaml:"preferred"`
	Supported []RuntimeMode `json:"supported"          yaml:"supported"`
	// backward-compat derived views (computed, not stored)
	DefaultRuntime   RuntimeMode `json:"default_runtime,omitempty"   yaml:"default_runtime,omitempty"`
	RuntimeReason    string      `json:"runtime_reason,omitempty"    yaml:"runtime_reason,omitempty"`
	GatewaySupported bool        `json:"gateway_supported,omitempty" yaml:"gateway_supported,omitempty"`
}

// SDKGatewaySupport describes SDK-level gateway integration details.
type SDKGatewaySupport struct {
	SDKPackage string `json:"sdk_package,omitempty" yaml:"sdk_package,omitempty"`
	SDKVersion string `json:"sdk_version,omitempty" yaml:"sdk_version,omitempty"`
}

// BrokerSupport describes direct-brokered runtime configuration.
type BrokerSupport struct {
	Strategy string `json:"strategy" yaml:"strategy"` // e.g. "dropbox_oauth"
}

// ProxyRoute describes a single proxy routing rule.
type ProxyRoute struct {
	PathPrefix  string `json:"path_prefix"  yaml:"path_prefix"`
	UpstreamURL string `json:"upstream_url" yaml:"upstream_url"`
}

// ProxySupport describes gateway-proxy runtime configuration.
type ProxySupport struct {
	Routes []ProxyRoute `json:"routes,omitempty" yaml:"routes,omitempty"`
}

// SandboxProfileRef references a sandbox security profile.
type SandboxProfileRef struct {
	Name    string `json:"name"              yaml:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// SDKCompat describes SDK compatibility metadata.
type SDKCompat struct {
	Language string `json:"language,omitempty" yaml:"language,omitempty"`
	Package  string `json:"package,omitempty"  yaml:"package,omitempty"`
	Version  string `json:"version,omitempty"  yaml:"version,omitempty"`
}

// SecretField describes a field whose value must be stored as a secret in the vault.
type SecretField struct {
	Name           string   `json:"name"                      yaml:"name"`
	Label          string   `json:"label,omitempty"           yaml:"label,omitempty"`
	Description    string   `json:"description,omitempty"     yaml:"description,omitempty"`
	Required       bool     `json:"required"                  yaml:"required"`
	EnvVar         string   `json:"env_var,omitempty"         yaml:"env_var,omitempty"`
	Sensitive      bool     `json:"sensitive"                 yaml:"sensitive"`
	SecretKind     string   `json:"secret_kind,omitempty"     yaml:"secret_kind,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty" yaml:"required_scopes,omitempty"`
}

// TemplateDocs holds supplementary documentation URLs for a provider template.
type TemplateDocs struct {
	CredentialsURL string `json:"credentials_url,omitempty" yaml:"credentials_url,omitempty"`
	ScopesURL      string `json:"scopes_url,omitempty"      yaml:"scopes_url,omitempty"`
}

// ConfigField describes a non-secret configuration field for a provider.
type ConfigField struct {
	Name        string `json:"name"                  yaml:"name"`
	Label       string `json:"label,omitempty"       yaml:"label,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool   `json:"required"              yaml:"required"`
	Default     string `json:"default,omitempty"     yaml:"default,omitempty"`
	EnvVar      string `json:"env_var,omitempty"     yaml:"env_var,omitempty"`
}

// Capability is a named feature advertised by a provider connection.
type Capability struct {
	Name        string `json:"name"                  yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// TestStrategy describes how to verify a provider connection is healthy.
type TestStrategy struct {
	Kind     string          `json:"kind"     yaml:"kind"` // "http_get" | "http_post" | "sdk_call"
	Endpoint string          `json:"endpoint" yaml:"endpoint"`
	Expect   TestExpectation `json:"expect"   yaml:"expect"`
}

// TestExpectation describes the expected response from a TestStrategy.
type TestExpectation struct {
	StatusCode int      `json:"status_code,omitempty" yaml:"status_code,omitempty"`
	Markers    []string `json:"markers,omitempty"     yaml:"markers,omitempty"` // expected body substrings (allowlist)
}

// AuthPlacement describes where authentication credentials are placed in requests.
type AuthPlacement struct {
	In     string `json:"in"               yaml:"in"`               // "header" | "query" | "body"
	Name   string `json:"name"             yaml:"name"`             // header/param name, e.g. "Authorization"
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"` // e.g. "Bearer"
}

// RateLimitSpec describes rate-limiting parameters.
type RateLimitSpec struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty" yaml:"requests_per_minute,omitempty"`
	BurstSize         int `json:"burst_size,omitempty"          yaml:"burst_size,omitempty"`
}

// InjectionRule describes how credentials are injected into a subprocess.
type InjectionRule struct {
	EnvVar string `json:"env_var" yaml:"env_var"`
	Source string `json:"source"  yaml:"source"` // "secret_field" reference
}

// RedactionRule describes a redaction pattern applied to subprocess output.
type RedactionRule struct {
	Pattern     string `json:"pattern"     yaml:"pattern"`     // regex pattern
	Replacement string `json:"replacement" yaml:"replacement"` // replacement string (e.g. "****")
}

// GatewayAction describes a single gateway-level action for a provider.
// Forward-compat: fields ExchangeStrategy through LLMSessionDeny are stored and
// round-tripped but not semantically honoured until Phase 9 / Phase 13.
type GatewayAction struct {
	Name        string `json:"name"                  yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// SDKPath is the exact path the SDK client sends (e.g. "/v1/chat/completions").
	// When non-empty, gateway_sdk mode registers this as the inbound route path
	// instead of the synthesised "/sdk/<provider>/v1/<action.Name>" fallback.
	SDKPath string `json:"sdk_path,omitempty" yaml:"sdk_path,omitempty"`
	// Method is the HTTP method for this action (default "POST").
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	// UpstreamPath is the exact path to forward to on the upstream host.
	// When empty, falls back to the TestStrategy endpoint path.
	UpstreamPath string `json:"upstream_path,omitempty" yaml:"upstream_path,omitempty"`
	// Forward-compat Phase 9/13 fields:
	ExchangeStrategy       ExchangeStrategy `json:"exchange_strategy,omitempty"       yaml:"exchange_strategy,omitempty"`
	MaxAccessTokenTTL      string           `json:"max_access_token_ttl,omitempty"    yaml:"max_access_token_ttl,omitempty"`
	RequiredScopes         []string         `json:"required_scopes,omitempty"         yaml:"required_scopes,omitempty"`
	MaskingProfile         string           `json:"masking_profile,omitempty"         yaml:"masking_profile,omitempty"`
	AllowedFields          []string         `json:"allowed_fields,omitempty"          yaml:"allowed_fields,omitempty"`
	RiskLabel              string           `json:"risk_label,omitempty"              yaml:"risk_label,omitempty"`
	UntrustedContentSource bool             `json:"untrusted_content_source,omitempty" yaml:"untrusted_content_source,omitempty"`
	LLMSessionDeny         bool             `json:"llm_session_deny,omitempty"        yaml:"llm_session_deny,omitempty"`
}

// ConnectionTemplate is the canonical description of a provider's connection
// requirements, runtime support, and security metadata.
type ConnectionTemplate struct {
	// Identity
	Provider    string       `json:"provider"              yaml:"provider"`     // kebab-case slug, e.g. "openrouter"
	DisplayName string       `json:"display_name"          yaml:"display_name"` // human-readable, e.g. "OpenRouter"
	Category    string       `json:"category"              yaml:"category"`     // e.g. "ai", "observability", "storage"
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	DocsURL     string       `json:"docs_url,omitempty"    yaml:"docs_url,omitempty"`
	Docs        TemplateDocs `json:"docs,omitempty"        yaml:"docs,omitempty"`
	// Actions is the EPIC-20 action catalog: named HTTP operations available via
	// `keylatch call <connection> <action>`. Optional — omit for providers that
	// do not expose scoped HTTP actions.
	Actions map[string]template.Action `json:"actions,omitempty" yaml:"actions,omitempty"`

	// Credential schema
	SecretFields []SecretField     `json:"secret_fields"           yaml:"secret_fields"`
	ConfigFields []ConfigField     `json:"config_fields,omitempty" yaml:"config_fields,omitempty"`
	EnvMappings  map[string]string `json:"env_mappings,omitempty"  yaml:"env_mappings,omitempty"` // field_name -> env_var

	// Auth
	AuthFlow      AuthFlow      `json:"auth_flow"                yaml:"auth_flow"`
	AuthPlacement AuthPlacement `json:"auth_placement,omitempty" yaml:"auth_placement,omitempty"`

	// Storage
	StoragePathTpl string `json:"storage_path_tpl" yaml:"storage_path_tpl"` // e.g. "{{namespace}}/ai/{{provider}}/{{account}}"

	// Trust
	TrustLevel TrustLevel `json:"trust_level" yaml:"trust_level"`

	// Multi-account support
	MultiAccount bool `json:"multi_account,omitempty" yaml:"multi_account,omitempty"`

	// Runtime
	RuntimeSupport RuntimeSupport `json:"runtime_support"       yaml:"runtime_support"`
	SDKCompat      SDKCompat      `json:"sdk_compat,omitempty"  yaml:"sdk_compat,omitempty"`

	// Capabilities
	Capabilities []Capability `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`

	// Gateway actions (forward-compat)
	GatewayActions []GatewayAction `json:"gateway_actions,omitempty" yaml:"gateway_actions,omitempty"`

	// Security
	AllowedCommandPrefixes []string        `json:"allowed_command_prefixes,omitempty" yaml:"allowed_command_prefixes,omitempty"`
	InjectionRules         []InjectionRule `json:"injection_rules,omitempty"          yaml:"injection_rules,omitempty"`
	Redaction              []RedactionRule `json:"redaction,omitempty"                yaml:"redaction,omitempty"`
	OverbroadScopes        []string        `json:"overbroad_scopes,omitempty"         yaml:"overbroad_scopes,omitempty"`
	RateLimit              RateLimitSpec   `json:"rate_limit,omitempty"               yaml:"rate_limit,omitempty"`

	// Test strategy
	TestStrategy TestStrategy `json:"test_strategy" yaml:"test_strategy"`
}

// Get looks up a provider template by slug.
// Returns ErrProviderNotFound if provider is not registered.
func Get(provider string) (ConnectionTemplate, error) {
	return catalogGet(provider)
}

// List returns all registered templates in stable sorted order.
func List() []ConnectionTemplate {
	return catalogList()
}

// ListByCategory returns all templates in the given category.
func ListByCategory(cat string) []ConnectionTemplate {
	return catalogListByCategory(cat)
}

// GetTrustLevel returns the TrustLevel for a registered provider.
// Returns ErrProviderNotFound if provider is not registered.
func GetTrustLevel(provider string) (TrustLevel, error) {
	t, err := catalogGet(provider)
	if err != nil {
		return 0, err
	}
	return t.TrustLevel, nil
}
