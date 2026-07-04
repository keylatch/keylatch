// Package proxy implements the gateway_proxy runtime profile schema,
// TLS CA management, and env injection.
package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/keylatch/keylatch/internal/policy"
)

// ProxyProfile describes a gateway_proxy runtime configuration.
type ProxyProfile struct {
	ID     string       `json:"id"`
	Mode   string       `json:"mode"` // must be "gateway_proxy"
	Hosts  []string     `json:"hosts"`
	Routes []ProxyRoute `json:"routes"`
	TLS    ProxyTLS     `json:"tls"`
	SSRF   ProxySsrf    `json:"ssrf"`
}

// ProxyRoute describes a single proxy routing rule.
type ProxyRoute struct {
	Method        string        `json:"method"`
	Path          string        `json:"path"`
	Capability    string        `json:"capability"`
	AuthInjection AuthInjection `json:"auth_injection"`
	Masking       MaskingLevel  `json:"masking"`
}

// MaskingLevel describes the response masking level for a route.
type MaskingLevel string

const (
	MaskingLevelBasic        MaskingLevel = "basic"
	MaskingLevelStrict       MaskingLevel = "strict"
	MaskingLevelMetadataOnly MaskingLevel = "metadata_only"
	MaskingLevelBlockBody    MaskingLevel = "block_body"
)

// AuthInjection describes how auth credentials are injected into upstream requests.
type AuthInjection struct {
	// Placement is "header" | "query" | "basic".
	Placement string `json:"placement"`
	// Name is the header or query param name.
	Name string `json:"name"`
	// Value may contain {{ secret.<path> }} template syntax.
	Value string `json:"value"`
}

// ProxyTLS describes TLS CA configuration for the proxy.
type ProxyTLS struct {
	// Mode is "local_ca" | "trust_store_install".
	Mode string `json:"mode"`
	// CAKeyStorage must be "keyring".
	CAKeyStorage string `json:"ca_key_storage"`
	// InstallTrustStore installs the CA cert into the OS trust store.
	InstallTrustStore bool `json:"install_trust_store"`
	// InjectCAEnv injects CA cert path as env vars into child processes.
	InjectCAEnv bool `json:"inject_ca_env"`
}

// ProxySsrf describes SSRF prevention settings.
type ProxySsrf struct {
	DenyPrivateRanges           bool `json:"deny_private_ranges"`
	ResolveAndVerifyEachRequest bool `json:"resolve_and_verify_each_request"`
}

// ParseProxyProfile parses a ProxyProfile from JSON.
// Returns an error if the required mode or TLS fields are invalid.
func ParseProxyProfile(data []byte) (ProxyProfile, error) {
	var p ProxyProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return ProxyProfile{}, fmt.Errorf("proxy_profile: parse: %w", err)
	}
	// N-12: validate Mode field using the canonical runtime mode validator.
	// gateway_proxy is a valid runtime mode, so this validates correctly without
	// breaking valid profiles.
	if p.Mode != "" {
		if err := policy.ValidateRuntimeMode(p.Mode); err != nil {
			return ProxyProfile{}, fmt.Errorf("proxy profile: invalid mode: %w", err)
		}
	}
	if err := validateTLSMode(p.TLS); err != nil {
		return ProxyProfile{}, err
	}
	return p, nil
}

// validateTLSMode returns an error for invalid TLS configuration.
func validateTLSMode(tls ProxyTLS) error {
	switch tls.Mode {
	case "local_ca", "trust_store_install", "":
		// valid
	default:
		return fmt.Errorf("proxy_profile: invalid tls.mode %q; must be \"local_ca\" or \"trust_store_install\"", tls.Mode)
	}
	if tls.Mode != "" && tls.CAKeyStorage != "keyring" {
		return fmt.Errorf("proxy_profile: tls.ca_key_storage must be \"keyring\"; got %q", tls.CAKeyStorage)
	}
	return nil
}
